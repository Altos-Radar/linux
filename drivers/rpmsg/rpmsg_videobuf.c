// SPDX-License-Identifier: GPL-2.0-only
/*
 * RPMSG Videobuf
 *
 * Michael Wu <mwu.code@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/videodev2.h>
#include <linux/workqueue.h>
#include <linux/circ_buf.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-mem2mem.h>
#include <media/videobuf2-dma-contig.h>
#include <media/videobuf2-v4l2.h>

#include "rpmsg_videobuf_proto.h"

union query_resp {
	struct rpvb_msg_query_resp_header header;
	struct rpvb_msg_query_resp_base base;
	struct rpvb_msg_query_resp_queue queue;
	struct rpvb_msg_query_resp_control ctrl;
};

struct resp_queue {
	struct work_struct work;
	int head;
	int tail;
	struct rpvb_priv *priv;
	union query_resp queue[32];
};

struct rpvb_queue_info {
	u32 stride;
	u32 size;
};

struct rpvb_priv {
	struct rpmsg_endpoint *ept;
	struct v4l2_ctrl_handler ctrl_handler;
	struct v4l2_device v4l2_dev;
	struct video_device vdev;
	struct v4l2_m2m_dev *m2m_dev;
	spinlock_t job_lock;
	struct v4l2_m2m_ctx *current_job_ctx;
	u64 job_queues_done;

	struct resp_queue *resp_queue;
	char name[32];
	u16 tx_queues;
	u16 rx_queues;
	u32 controls;
	u32 controls_registered;
	u32 width;
	u32 height;
	u32 fourcc;
	struct mutex lock;
	struct rpvb_queue_info *tx_queue_info;
	struct rpvb_queue_info *rx_queue_info;
};

struct rpvb_ctx {
	struct v4l2_fh fh;
	struct rpvb_priv *priv;
	struct mutex lock;
};

static int rpvb_queue_setup(struct vb2_queue *q,
			    unsigned int *num_buffers, unsigned int *num_planes,
			    unsigned int sizes[], struct device *alloc_devs[])
{
	struct rpvb_ctx *ctx = q->drv_priv;
	struct rpvb_priv *priv = ctx->priv;
	bool tx_queue = q == &ctx->fh.m2m_ctx->out_q_ctx.q;
	if (*num_planes) {
		if (tx_queue) {
			if (*num_planes != priv->tx_queues)
				return -EINVAL;
			for (int i = 0; i < priv->tx_queues; ++i) {
				if (sizes[i] < priv->tx_queue_info[i].size)
					return -EINVAL;
			}
		} else {
			if (*num_planes != priv->rx_queues)
				return -EINVAL;
			for (int i = 0; i < priv->rx_queues; ++i) {
				if (sizes[i] < priv->rx_queue_info[i].size)
					return -EINVAL;
			}
		}
		return 0;
	}

	if (tx_queue) {
		*num_planes = priv->tx_queues;
		for (int i = 0; i < priv->tx_queues; ++i) {
			sizes[i] = priv->tx_queue_info[i].size;
		}
	} else {
		*num_planes = priv->rx_queues;
		for (int i = 0; i < priv->rx_queues; ++i) {
			sizes[i] = priv->rx_queue_info[i].size;
		}
	}
	return 0;
}

static int rpvb_buf_out_validate(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	if (vbuf->field == V4L2_FIELD_ANY)
		vbuf->field = V4L2_FIELD_NONE;
	if (vbuf->field != V4L2_FIELD_NONE) {
		return -EINVAL;
	}
	return 0;
}

static int rpvb_start_streaming(struct vb2_queue *q, unsigned int count)
{
	return 0;
}

static void rpvb_stop_streaming(struct vb2_queue *q)
{
	struct rpvb_ctx *ctx = q->drv_priv;
	if (q->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		struct vb2_v4l2_buffer *vbuf;
		while ((vbuf = v4l2_m2m_src_buf_remove(ctx->fh.m2m_ctx))) {
			v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
		}
	} else {
		struct vb2_v4l2_buffer *vbuf;
		while ((vbuf = v4l2_m2m_dst_buf_remove(ctx->fh.m2m_ctx))) {
			v4l2_m2m_buf_done(vbuf, VB2_BUF_STATE_ERROR);
		}
	}
}

static int rpvb_buf_prepare(struct vb2_buffer *vb)
{
	struct rpvb_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	struct rpvb_priv *priv = ctx->priv;
	if (vb->vb2_queue->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		if (vb->num_planes != priv->tx_queues) {
			return -EINVAL;
		}
		for (int i = 0; i < priv->tx_queues; ++i) {
			if (vb2_plane_size(vb, i) < priv->tx_queue_info[i].size)
				return -EINVAL;
		}
	} else if (vb->vb2_queue->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		if (vb->num_planes != priv->rx_queues) {
			return -EINVAL;
		}
		for (int i = 0; i < priv->rx_queues; ++i) {
			if (vb2_plane_size(vb, i) < priv->rx_queue_info[i].size)
				return -EINVAL;
		}
	} else {
		// ???
		return -EINVAL;
	}
	return 0;
}

static void rpvb_buf_queue(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);
	struct rpvb_ctx *ctx = vb2_get_drv_priv(vb->vb2_queue);
	v4l2_m2m_buf_queue(ctx->fh.m2m_ctx, vbuf);
}

static const struct vb2_ops rpvb_vb2_ops = {
	.queue_setup		= rpvb_queue_setup,
	.wait_prepare		= vb2_ops_wait_prepare,
	.wait_finish		= vb2_ops_wait_finish,
	.buf_out_validate	= rpvb_buf_out_validate,
	.start_streaming	= rpvb_start_streaming,
	.stop_streaming		= rpvb_stop_streaming,
	.buf_prepare		= rpvb_buf_prepare,
	.buf_queue		= rpvb_buf_queue,
};

static void rpvb_device_run(void *p)
{
	struct rpvb_ctx *ctx = p;
	struct rpvb_priv *priv = ctx->priv;
	struct vb2_v4l2_buffer *src_buf, *dst_buf;
	u8 msg_buf[sizeof(struct rpvb_msg_queue) + sizeof(uint64_t) * 1 + 7];
	struct rpvb_msg_queue *msg = (struct rpvb_msg_queue *)(((uintptr_t)msg_buf + 7) & ~7);

	src_buf = v4l2_m2m_next_src_buf(ctx->fh.m2m_ctx);
	dst_buf = v4l2_m2m_next_dst_buf(ctx->fh.m2m_ctx);

	spin_lock(&priv->job_lock);
	priv->current_job_ctx = ctx->fh.m2m_ctx;
	priv->job_queues_done = (1 << priv->tx_queues) - 1;
	spin_unlock(&priv->job_lock);

	msg->type = RPVB_MSG_TYPE_QUEUE;
	msg->sections = 1;
	for (int i = 0; i < priv->rx_queues; ++i) {
		int ret;
		msg->queue_index = priv->tx_queues + i;
		msg->size = priv->rx_queue_info[i].size;
		msg->addr[0] = vb2_dma_contig_plane_dma_addr(&dst_buf->vb2_buf, i);
		ret = rpmsg_send(priv->ept, msg, sizeof(*msg) + sizeof(uint64_t));
		if (ret)
			dev_warn(priv->v4l2_dev.dev, "Could not queue rx. index %d\n", i);
		vb2_set_plane_payload(&dst_buf->vb2_buf, i, priv->rx_queue_info[i].size);
	}
	for (int i = 0; i < priv->tx_queues; ++i) {
		int ret;
		msg->queue_index = i;
		msg->size = src_buf->vb2_buf.planes[i].length;
		msg->addr[0] = vb2_dma_contig_plane_dma_addr(&src_buf->vb2_buf, i);
		dma_sync_single_for_cpu(priv->v4l2_dev.dev, msg->addr[0], msg->size, DMA_TO_DEVICE);
		ret = rpmsg_send(priv->ept, msg, sizeof(*msg) + sizeof(uint64_t));
		if (ret)
			dev_warn(priv->v4l2_dev.dev, "Could not queue tx. index %d\n", i);
	}
}

static const struct v4l2_m2m_ops rpvb_m2m_ops = {
	.device_run = rpvb_device_run,
};

static int rpvb_querycap(struct file *file, void *fh, struct v4l2_capability *cap)
{
	struct rpvb_priv *priv = video_drvdata(file);
	strlcpy(cap->driver, KBUILD_MODNAME, sizeof(cap->driver));
	strlcpy(cap->card, priv->name, sizeof(cap->card));
	return 0;
}

static int rpvb_g_fmt(struct rpvb_priv *priv, struct v4l2_format *f, uint16_t queue_len, struct rpvb_queue_info *info)
{
	struct v4l2_pix_format_mplane *pix = &f->fmt.pix_mp;
	pix->width = priv->width;
	pix->height = priv->height;
	pix->pixelformat = priv->fourcc;
	pix->field = V4L2_FIELD_NONE;
	pix->colorspace = V4L2_COLORSPACE_RAW;
	pix->num_planes = min(queue_len, (uint16_t)VIDEO_MAX_PLANES);
	for (uint8_t i = 0; i < pix->num_planes; ++i) {
		pix->plane_fmt[i].sizeimage = priv->rx_queue_info[i].size;
		pix->plane_fmt[i].bytesperline = priv->rx_queue_info[i].stride;
		memset(pix->plane_fmt[i].reserved, 0, sizeof(pix->plane_fmt[i].reserved));
	}
	pix->flags = 0;
	pix->ycbcr_enc = 0;
	pix->quantization = V4L2_QUANTIZATION_DEFAULT;
	pix->xfer_func = V4L2_XFER_FUNC_NONE;
	memset(pix->reserved, 0, sizeof(pix->reserved));
	return 0;
}

static int rpvb_g_fmt_vid_cap_mplane(struct file *file, void *fh, struct v4l2_format *f)
{
	struct rpvb_priv *priv = video_drvdata(file);
	return rpvb_g_fmt(priv, f, priv->rx_queues, priv->rx_queue_info);
}

static int rpvb_g_fmt_vid_out_mplane(struct file *file, void *fh, struct v4l2_format *f)
{
	struct rpvb_priv *priv = video_drvdata(file);
	return rpvb_g_fmt(priv, f, priv->tx_queues, priv->tx_queue_info);
}

static const struct v4l2_ioctl_ops rpvb_ioctl_ops = {
	.vidioc_querycap = rpvb_querycap,

	.vidioc_g_fmt_vid_cap_mplane = rpvb_g_fmt_vid_cap_mplane,

	.vidioc_g_fmt_vid_out_mplane = rpvb_g_fmt_vid_out_mplane,

	.vidioc_reqbufs = v4l2_m2m_ioctl_reqbufs,
	.vidioc_create_bufs = v4l2_m2m_ioctl_create_bufs,
	.vidioc_querybuf = v4l2_m2m_ioctl_querybuf,
	.vidioc_qbuf = v4l2_m2m_ioctl_qbuf,
	.vidioc_dqbuf = v4l2_m2m_ioctl_dqbuf,
	.vidioc_expbuf = v4l2_m2m_ioctl_expbuf,
	.vidioc_streamon = v4l2_m2m_ioctl_streamon,
	.vidioc_streamoff = v4l2_m2m_ioctl_streamoff,

	//.vidioc_log_status = v4l2_ctrl_log_status,
	//.vidioc_subscribe_event = v4l2_ctrl_subscribe_event,
	//.vidioc_unsubscribe_event = v4l2_event_unsubscribe,
};

static int rpvb_queue_init(void *p, struct vb2_queue *src_vq, struct vb2_queue *dst_vq)
{
	int ret;
	struct rpvb_ctx *ctx = p;
	struct rpvb_priv *priv = ctx->priv;

	src_vq->type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	src_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	src_vq->dev = priv->v4l2_dev.dev;
	src_vq->drv_priv = ctx;
	src_vq->ops = &rpvb_vb2_ops;
	src_vq->mem_ops = &vb2_dma_contig_memops;
	src_vq->min_buffers_needed = 1;
	src_vq->lock = &ctx->lock;
	src_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	ret = vb2_queue_init(src_vq);
	if (ret)
		return ret;

	dst_vq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	dst_vq->io_modes = VB2_MMAP | VB2_DMABUF;
	dst_vq->dev = priv->v4l2_dev.dev;
	dst_vq->drv_priv = ctx;
	dst_vq->ops = &rpvb_vb2_ops;
	dst_vq->mem_ops = &vb2_dma_contig_memops;
	dst_vq->lock = &ctx->lock;
	dst_vq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	return vb2_queue_init(dst_vq);
}

static int rpvb_open(struct file *file)
{
	int ret = 0;
	struct rpvb_priv *priv = video_drvdata(file);
	struct rpvb_ctx *ctx;
	if (mutex_lock_interruptible(&priv->lock))
		return -ERESTARTSYS;

	ctx = kzalloc(sizeof(struct rpvb_ctx), GFP_KERNEL);
	if (!ctx) {
		ret = -ENOMEM;
		goto unlock;
	}

	mutex_init(&ctx->lock);
	v4l2_fh_init(&ctx->fh, video_devdata(file));
	file->private_data = &ctx->fh;
	ctx->priv = priv;
	ctx->fh.m2m_ctx = v4l2_m2m_ctx_init(priv->m2m_dev, ctx, &rpvb_queue_init);

	v4l2_fh_add(&ctx->fh);

unlock:
	mutex_unlock(&priv->lock);
	return ret;
}

static int rpvb_release(struct file *file)
{
	struct rpvb_priv *priv = video_drvdata(file);
	struct rpvb_ctx *ctx = container_of(file->private_data, struct rpvb_ctx, fh);
	v4l2_fh_del(&ctx->fh);
	v4l2_fh_exit(&ctx->fh);
	mutex_lock(&priv->lock);
	v4l2_m2m_ctx_release(ctx->fh.m2m_ctx);
	mutex_unlock(&priv->lock);
	kfree(ctx);
	return 0;
}

static const struct v4l2_file_operations rpvb_fops = {
	.owner = THIS_MODULE,
	.open = rpvb_open,
	.release = rpvb_release,
	.unlocked_ioctl = video_ioctl2,
	.mmap = v4l2_m2m_fop_mmap,
	.poll = v4l2_m2m_fop_poll,
};

static int rpvb_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct rpvb_priv *priv = ctrl->priv;
	int ret;
	switch (ctrl->type) {
	case V4L2_CTRL_TYPE_INTEGER:
	case V4L2_CTRL_TYPE_BOOLEAN: {
		struct rpvb_msg_set_control_int32 msg = {
			.type = RPVB_MSG_TYPE_SET_CONTROL,
			.ctrl_type = ctrl->type,
			.ctrl_index = ctrl->id - V4L2_CID_USER_BASE,
			.val = ctrl->val,
		};
		ret = rpmsg_send(priv->ept, &msg, sizeof(msg));
		break;
	}
	case V4L2_CTRL_TYPE_INTEGER64: {
		struct rpvb_msg_set_control_int64 msg = {
                        .type = RPVB_MSG_TYPE_SET_CONTROL,
                        .ctrl_type = ctrl->type,
                        .ctrl_index = ctrl->id - V4L2_CID_USER_BASE,
                        .val = *ctrl->p_new.p_s64,
                };
                ret = rpmsg_send(priv->ept, &msg, sizeof(msg));
		break;
	}
	case V4L2_CTRL_TYPE_U8:
	case V4L2_CTRL_TYPE_U16:
	case V4L2_CTRL_TYPE_U32: {
		struct rpvb_msg_set_control_compound msg = {
			.header = {
				.type = RPVB_MSG_TYPE_SET_CONTROL,
				.ctrl_type = ctrl->type,
				.ctrl_index = ctrl->id - V4L2_CID_USER_BASE,
			},
		};
		int chunk_size = sizeof(msg.data) / ctrl->elem_size;
		for (int i = 0; i < ctrl->elems; i += chunk_size) {
			int chunk_len = min((int)ctrl->elems - i, chunk_size);
			int chunk_start_idx = i * ctrl->elem_size;
			int chunk_len_bytes = chunk_len * ctrl->elem_size;
			memcpy(&msg.data, &ctrl->p_new.p_u8[chunk_start_idx], chunk_len_bytes);
			msg.header.start_index = i;
			msg.header.elems = chunk_len;
			ret = rpmsg_send(priv->ept, &msg, sizeof(msg.header) + chunk_len_bytes);
			if (ret)
				break;
		}
		break;
	}
	default:
		dev_warn(priv->v4l2_dev.dev, "Unsupported control type: %d\n", ctrl->type);
		return -EINVAL;
	}
	if (ret)
		dev_warn(priv->v4l2_dev.dev, "Failed to send set control message: %d\n", ret);
	return ret;
}

static const struct v4l2_ctrl_ops rpvb_ctrl_ops = {
	.s_ctrl = rpvb_s_ctrl,
};

static void rpvb_device_release(struct video_device *vdev)
{
}

static void rpvb_query_resp_work(struct work_struct *work)
{
	struct resp_queue *queue = container_of(work, struct resp_queue, work);
	struct rpvb_priv *priv = queue->priv;
	int head = READ_ONCE(queue->head);
	int tail = READ_ONCE(queue->tail);
	bool ready = true;
	while (head != tail) {
		union query_resp *entry = &queue->queue[tail];
		struct rpvb_msg_query_resp_header *resp_header = &entry->header;
		tail = (tail + 1) % ARRAY_SIZE(queue->queue);
		if (resp_header->subtype == RPVB_QUERY_RESP_BASE) {
			struct rpvb_msg_query_resp_base *base = &entry->base;
			if (base->rx_queues > 8 || base->tx_queues > 8) {
				dev_warn(priv->v4l2_dev.dev, "Too many queues requested\n");
				continue;
			}
			if (!base->rx_queues || !base->tx_queues) {
				dev_warn(priv->v4l2_dev.dev, "Must have at least one tx and rx queue\n");
				continue;
			}
			if (priv->tx_queue_info) {
				dev_warn(priv->v4l2_dev.dev, "Already received base response\n");
				continue;
			}
			priv->tx_queue_info = kzalloc(
				sizeof(priv->tx_queue_info[0]) * base->tx_queues, GFP_KERNEL);
			if (!priv->tx_queue_info) {
				dev_warn(priv->v4l2_dev.dev, "Could not allocate tx_queue_info\n");
				continue;
			}
			priv->rx_queue_info = kzalloc(
				sizeof(priv->rx_queue_info[0]) * base->rx_queues, GFP_KERNEL);
			if (!priv->rx_queue_info) {
				kfree(priv->tx_queue_info);
				priv->tx_queue_info = NULL;
				dev_warn(priv->v4l2_dev.dev, "Could not allocate rx_queue_info\n");
				continue;
			}
			memcpy(priv->name, base->name, sizeof(priv->name));
			priv->rx_queues = base->rx_queues;
			priv->tx_queues = base->tx_queues;
			priv->controls = base->controls;
			priv->width = base->width;
			priv->height = base->height;
			priv->fourcc = base->fourcc;
			v4l2_ctrl_handler_init(&priv->ctrl_handler, base->controls);
		} else if (resp_header->subtype == RPVB_QUERY_RESP_QUEUE) {
			struct rpvb_msg_query_resp_queue *queue = &entry->queue;
			struct rpvb_queue_info *info = NULL;
			if (queue->queue_index >= (priv->rx_queues + priv->tx_queues)) {
				dev_warn(priv->v4l2_dev.dev, "Invalid queue index: %d\n", queue->queue_index);
				continue;
			}
			if (queue->size == 0) {
				dev_warn(priv->v4l2_dev.dev, "Invalid queue buffer size: %d\n", queue->size);
				continue;
			}
			if (!priv->tx_queue_info) {
				dev_warn(priv->v4l2_dev.dev, "Need base query resp first\n");
				continue;
			}
			if (queue->queue_index < priv->tx_queues) {
				info = &priv->tx_queue_info[queue->queue_index];
			} else {
				info = &priv->rx_queue_info[queue->queue_index - priv->tx_queues];
			}
			info->stride = queue->stride;
			info->size = queue->size;
		} else if (resp_header->subtype == RPVB_QUERY_RESP_CONTROL) {
			struct rpvb_msg_query_resp_control *ctrl_info = &entry->ctrl;
			struct v4l2_ctrl_config config = {
				.ops = &rpvb_ctrl_ops,
				.id = V4L2_CID_USER_BASE + ctrl_info->index,
				.type = ctrl_info->ctrl_type,
				.min = ctrl_info->minimum,
				.max = ctrl_info->maximum,
				.step = ctrl_info->step,
				.def = ctrl_info->default_value,
				.elem_size = ctrl_info->elem_size,
			};
			struct v4l2_ctrl *ctrl;
			memcpy(config.dims, ctrl_info->dims, sizeof(config.dims));
			if (priv->controls_registered >= priv->controls) {
				dev_warn(priv->v4l2_dev.dev, "More controls than registered\n");
				continue;
			}
			config.name = kstrndup(ctrl_info->name, sizeof(ctrl_info->name), GFP_KERNEL);
			if (!config.name) {
				dev_warn(priv->v4l2_dev.dev, "Could not allocate name\n");
				continue;
			}
			switch (ctrl_info->ctrl_type) {
			case RPVB_CTRL_TYPE_INT:
			case RPVB_CTRL_TYPE_BOOLEAN:
			case RPVB_CTRL_TYPE_INT64:
			case RPVB_CTRL_COMPOUND_U8:
			case RPVB_CTRL_COMPOUND_U16:
			case RPVB_CTRL_COMPOUND_U32:
				break;
			default:
				dev_warn(priv->v4l2_dev.dev, "Unknown control type: 0x%x\n",
					ctrl_info->ctrl_type);
				break;
			}
			ctrl = v4l2_ctrl_new_custom(&priv->ctrl_handler, &config, priv);
			if (!ctrl)
				dev_warn(priv->v4l2_dev.dev, "Failed to register control %d\n",
					ctrl_info->index);
			priv->controls_registered++;
		}
	}
	WRITE_ONCE(queue->tail, tail);
	if (!priv->tx_queue_info) {
		return;
	}
	for (u16 i = 0; i < priv->tx_queues; ++i) {
		ready &= priv->tx_queue_info[i].size != 0;
	}
	for (u16 i = 0; i < priv->rx_queues; ++i) {
		ready &= priv->rx_queue_info[i].size != 0;
	}
	dev_warn(priv->v4l2_dev.dev, "%d == %d?\n", priv->controls_registered, priv->controls);
	ready &= priv->controls_registered == priv->controls;
	if (ready) {
		struct video_device *vdev = &priv->vdev;
		int ret;
		if (priv->ctrl_handler.error) {
			dev_err(priv->v4l2_dev.dev, "Failed to register controls: %d\n",
				priv->ctrl_handler.error);
			v4l2_ctrl_handler_free(&priv->ctrl_handler);
			kfree(priv->tx_queue_info);
			kfree(priv->rx_queue_info);
			priv->tx_queue_info = NULL;
			priv->rx_queue_info = NULL;
			return;
		}
		vdev->lock = &priv->lock;
		vdev->vfl_dir = VFL_DIR_M2M;
		vdev->release = rpvb_device_release;
		vdev->fops = &rpvb_fops;
		vdev->ioctl_ops = &rpvb_ioctl_ops;
		vdev->device_caps =
			V4L2_CAP_VIDEO_CAPTURE_MPLANE |
			V4L2_CAP_VIDEO_OUTPUT_MPLANE |
			V4L2_CAP_VIDEO_M2M_MPLANE | V4L2_CAP_STREAMING;
		vdev->v4l2_dev = &priv->v4l2_dev;
		vdev->ctrl_handler = &priv->ctrl_handler;
		video_set_drvdata(vdev, priv);
		ret = video_register_device(vdev, VFL_TYPE_VIDEO, -1);
		if (ret)
			dev_warn(priv->v4l2_dev.dev, "Failed to register video device: %d\n", ret);
	}
}

static int rpvb_cb(struct rpmsg_device *rpdev,
		    void *data, int len, void *p, u32 src)
{
	struct rpvb_priv *priv = p;
	struct rpvb_msg_header *header = data;
	if (len < sizeof(struct rpvb_msg_header)) {
		dev_warn(&rpdev->dev, "Received short message: %d bytes\n", len);
		return 0;
	}

	// video device not yet registered
	if (priv->vdev.fops == NULL) {
		struct rpvb_msg_query_resp_header *resp_header = data;
		int head = priv->resp_queue->head;
		if (header->type != RPVB_MSG_TYPE_QUERY_RESP) {
			dev_warn(&rpdev->dev, "Expected query resp, got: %d\n", header->type);
			return 0;
		}
		if (len < sizeof(*resp_header)) {
			dev_warn(&rpdev->dev, "Short query resp: %d bytes\n", len);
			return 0;
		}
		if (resp_header->subtype == RPVB_QUERY_RESP_BASE) {
			struct rpvb_msg_query_resp_base *base = data;
			if (len != sizeof(*base)) {
				dev_warn(&rpdev->dev, "Wrong query base resp len: %d bytes\n", len);
				return 0;
			}
			memcpy(&priv->resp_queue->queue[head].base, base, sizeof(*base));
		} else if (resp_header->subtype == RPVB_QUERY_RESP_QUEUE) {
			struct rpvb_msg_query_resp_queue *queue = data;
			if (len != sizeof(*queue)) {
				dev_warn(&rpdev->dev, "Wrong queue resp len: %d bytes\n", len);
				return 0;
			}
			memcpy(&priv->resp_queue->queue[head].queue, queue, sizeof(*queue));
		} else if (resp_header->subtype == RPVB_QUERY_RESP_CONTROL) {
			struct rpvb_msg_query_resp_control *ctrl = data;
			if (len != sizeof(*ctrl)) {
				dev_warn(&rpdev->dev, "Wrong queue resp len: %d bytes\n", len);
				return 0;
			}
			memcpy(&priv->resp_queue->queue[head].ctrl, ctrl, sizeof(*ctrl));
		} else {
			dev_warn(&rpdev->dev, "Unknown query response subtype: %d\n",
				 resp_header->subtype);
			return 0;
		}
		wmb();
		WRITE_ONCE(priv->resp_queue->head,
			(head + 1) % ARRAY_SIZE(priv->resp_queue->queue));
		schedule_work(&priv->resp_queue->work);
		return 0;
	}
	if (header->type == RPVB_MSG_TYPE_DEQUEUE) {
		unsigned long flags;
		struct rpvb_msg_dequeue *dequeue = data;
		struct v4l2_m2m_ctx *current_ctx;
		struct vb2_v4l2_buffer *dst_buf;
		u64 queue_mask = (1 << (priv->tx_queues + priv->rx_queues)) - 1;
		bool job_done = false;
		if (len != sizeof(*dequeue)) {
			dev_warn(&rpdev->dev, "Short dequeue: %d bytes\n", len);
			return 0;
		}
		spin_lock_irqsave(&priv->job_lock, flags);
		current_ctx = priv->current_job_ctx;
		priv->job_queues_done |= (1 << dequeue->queue_index) & queue_mask;
		job_done = priv->job_queues_done == queue_mask;
		if (job_done)
			priv->current_job_ctx = NULL;
		spin_unlock_irqrestore(&priv->job_lock, flags);
		if (current_ctx) {
			dst_buf = v4l2_m2m_next_dst_buf(current_ctx);
			vb2_set_plane_payload(&dst_buf->vb2_buf, dequeue->queue_index - priv->tx_queues, dequeue->size);
			if (job_done)
				v4l2_m2m_buf_done_and_job_finish(priv->m2m_dev, current_ctx, VB2_BUF_STATE_DONE);
		} else if (job_done)
			dev_warn(&rpdev->dev, "No context avaiable to dequeue with\n");
		return 0;
	}

	dev_warn(&rpdev->dev, "Unexpected message type: %d\n", header->type);
	return 0;
}

static int rpvb_probe(struct rpmsg_device *rpdev)
{
	int ret;
	struct rpvb_priv *priv;
	struct video_device *vdev;
	struct rpvb_msg_header query = {
		.type = RPVB_MSG_TYPE_QUERY,
	};

	priv = devm_kzalloc(&rpdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	rpdev->ept->priv = priv;
	priv->ept = rpdev->ept;

	dev_set_drvdata(&rpdev->dev, priv);
	priv->resp_queue = devm_kzalloc(&rpdev->dev, sizeof(priv->resp_queue[0]), GFP_KERNEL);
	if (!priv->resp_queue)
		return -ENOMEM;

	INIT_WORK(&priv->resp_queue->work, rpvb_query_resp_work);
	priv->resp_queue->priv = priv;

	ret = v4l2_device_register(&rpdev->dev, &priv->v4l2_dev);
	if (ret) {
		dev_warn(&rpdev->dev, "Failed to register V4L2 device: %d\n", ret);
		return ret;
	}

	if (!rpdev->dev.dma_mask)
		rpdev->dev.dma_mask = &rpdev->dev.coherent_dma_mask;
	ret = dma_set_coherent_mask(&rpdev->dev, DMA_BIT_MASK(48));
	if (ret) {
		dev_warn(&rpdev->dev, "Failed to set DMA coherent mask: %d\n", ret);
		goto unregister_v4l2;
	}

	mutex_init(&priv->lock);
	vdev = &priv->vdev;

	priv->m2m_dev = v4l2_m2m_init(&rpvb_m2m_ops);
	if (IS_ERR(priv->m2m_dev)) {
		ret = PTR_ERR(priv->m2m_dev);
		dev_warn(&rpdev->dev, "Failed to register mem2mem device: %d\n", ret);
		goto unregister_v4l2;
	}

	ret = rpmsg_send(rpdev->ept, &query, sizeof(query));
	if (ret) {
		dev_warn(&rpdev->dev, "Failed to send query: %d\n", ret);
		goto unregister_mem2mem;
	}

	dev_warn(&rpdev->dev, "rpmsg-videobuf registered\n");
	return 0;

unregister_mem2mem:
	v4l2_m2m_release(priv->m2m_dev);

unregister_v4l2:
	v4l2_device_unregister(&priv->v4l2_dev);

	return ret;
}

static void rpvb_remove(struct rpmsg_device *rpdev)
{
	struct rpvb_priv *priv = dev_get_drvdata(&rpdev->dev);

	if (priv->vdev.fops) {
		video_unregister_device(&priv->vdev);
	}
	v4l2_device_unregister(&priv->v4l2_dev);
	v4l2_m2m_release(priv->m2m_dev);
	priv->m2m_dev = NULL;
}

static struct rpmsg_device_id rpvb_id_table[] = {
	{ .name = "rpmsg_videobuf" },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpvb_id_table);

static struct rpmsg_driver rpvb_driver = {
	.drv.name	= KBUILD_MODNAME,
	.id_table	= rpvb_id_table,
	.probe		= rpvb_probe,
	.callback	= rpvb_cb,
	.remove		= rpvb_remove,
};

module_rpmsg_driver(rpvb_driver);

MODULE_DESCRIPTION("A RPMSG driver implementing V4L2/mem2mem");
MODULE_AUTHOR("Michael Wu");
MODULE_LICENSE("GPL v2");

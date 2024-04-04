// SPDX-License-Identifier: GPL-2.0-or-later
/* A video source representing a CSI virtual channel source
 *
 * Copyright 2023 Altos Radar, Michael Wu <michael.wu@altosradar.com>
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <media/v4l2-async.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-mc.h>
#include <media/v4l2-subdev.h>

struct csi_vc {
	struct v4l2_subdev subdev;
	struct v4l2_ctrl_handler ctrl_handler;
	struct v4l2_ctrl *link_freq;
	struct media_pad pads[3];
	s64 tx_link_freq;
};

static struct csi_vc *v4l2_subdev_to_priv(struct v4l2_subdev *subdev)
{
	return container_of(subdev, struct csi_vc, subdev);
}

static int csi_vc_enable_streams(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state, u32 pad, u64 streams_mask)
{
	return 0;
}

static int csi_vc_disable_streams(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *state, u32 pad, u64 streams_mask)
{
	return 0;
}

static int csi_vc_get_frame_desc(struct v4l2_subdev *sd, unsigned int pad,
				 struct v4l2_mbus_frame_desc *fd)
{
	if (pad != 0)
		return -EINVAL;

	memset(fd, 0, sizeof(*fd));
	fd->type = V4L2_MBUS_FRAME_DESC_TYPE_CSI2;
	fd->num_entries = 2;
	for (int i = 0; i < fd->num_entries; ++i) {
		struct v4l2_mbus_frame_desc_entry *entry = &fd->entry[i];
		entry->flags = 0;
		entry->stream = i;
		entry->pixelcode = MEDIA_BUS_FMT_UYVY8_1X16;
		entry->bus.csi2.vc = i;
		entry->bus.csi2.dt = 0;
	}

	return 0;
}

static int csi_vc_set_fmt(struct v4l2_subdev *sd,
			  struct v4l2_subdev_state *state,
			  struct v4l2_subdev_format *format)
{
	struct v4l2_mbus_framefmt *fmt;
	struct v4l2_subdev_stream_configs *stream_configs = &state->stream_configs;
	if (format->stream >= 2 || format->pad >= 3)
		return -EINVAL;

	fmt = v4l2_subdev_state_get_stream_format(state, format->pad, format->stream);
	if (!fmt)
		return -EINVAL;
	*fmt = format->format;

	fmt = v4l2_subdev_state_get_opposite_stream_format(state, format->pad, format->stream);
	if (!fmt)
		return -EINVAL;
	*fmt = format->format;

	return 0;
}

static int csi_vc_init_cfg(struct v4l2_subdev *sd, struct v4l2_subdev_state *state)
{
	dev_warn(sd->dev, "Initializing CSI-VC\n");
	struct v4l2_subdev_route routes[] = {
		{
			.sink_pad = 1,
			.sink_stream = 0,
			.source_pad = 0,
			.source_stream = 0,
			.flags = V4L2_SUBDEV_ROUTE_FL_ACTIVE,
		},
		{
			.sink_pad = 2,
			.sink_stream = 1,
			.source_pad = 0,
			.source_stream = 1,
			.flags = V4L2_SUBDEV_ROUTE_FL_ACTIVE,
		},
	};
	struct v4l2_subdev_krouting routing = {
		.num_routes = ARRAY_SIZE(routes),
		.routes = routes,
	};
	const struct v4l2_mbus_framefmt format = {
		.width = 640,
		.height = 480,
		.code = MEDIA_BUS_FMT_UYVY8_1X16,
		.field = V4L2_FIELD_NONE,
		.colorspace = V4L2_COLORSPACE_SRGB,
		.ycbcr_enc = V4L2_YCBCR_ENC_601,
		.quantization = V4L2_QUANTIZATION_LIM_RANGE,
		.xfer_func = V4L2_XFER_FUNC_SRGB,
	};
	int ret;

	ret = v4l2_subdev_routing_validate(sd, &routing, V4L2_SUBDEV_ROUTING_NO_1_TO_N);
	if (ret) {
		dev_warn(sd->dev, "Routing invalid: %d\n", ret);
		return ret;
	}

	ret = v4l2_subdev_set_routing_with_fmt(sd, state, &routing, &format);
	if (ret)
		dev_warn(sd->dev, "Failed to set routing: %d\n", ret);
	return ret;
}

static const struct v4l2_subdev_pad_ops csi_vc_pad_ops = {
	.enable_streams = csi_vc_enable_streams,
	.disable_streams = csi_vc_disable_streams,

	.get_frame_desc = csi_vc_get_frame_desc,
	.get_fmt = v4l2_subdev_get_fmt,
	.set_fmt = csi_vc_set_fmt,

	.init_cfg = csi_vc_init_cfg,
};

static const struct v4l2_subdev_ops csi_vc_subdev_ops = {
	.pad = &csi_vc_pad_ops,
};

static const struct media_entity_operations csi_vc_entity_ops = {
};

static int csi_vc_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct csi_vc *priv;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	platform_set_drvdata(pdev, priv);

	v4l2_subdev_init(&priv->subdev, &csi_vc_subdev_ops);
	priv->subdev.dev = dev;
	priv->subdev.flags = V4L2_SUBDEV_FL_HAS_DEVNODE | V4L2_SUBDEV_FL_STREAMS;
	snprintf(priv->subdev.name, V4L2_SUBDEV_NAME_SIZE, "%s.%s",
		 KBUILD_MODNAME, dev_name(&pdev->dev));

	priv->tx_link_freq = 720000000;
	v4l2_ctrl_handler_init(&priv->ctrl_handler, 1);
	priv->link_freq = v4l2_ctrl_new_int_menu(&priv->ctrl_handler, NULL, V4L2_CID_LINK_FREQ,
						 0, 0, &priv->tx_link_freq);
	ret = priv->ctrl_handler.error;
	if (ret)
		goto err_free;

	priv->subdev.ctrl_handler = &priv->ctrl_handler;

	priv->subdev.entity.function = MEDIA_ENT_F_VID_IF_BRIDGE;
	priv->pads[0].flags = MEDIA_PAD_FL_SOURCE;
	priv->pads[1].flags = MEDIA_PAD_FL_SINK;
	priv->pads[2].flags = MEDIA_PAD_FL_SINK;
	ret = media_entity_pads_init(&priv->subdev.entity, ARRAY_SIZE(priv->pads), priv->pads);
	priv->subdev.entity.ops = &csi_vc_entity_ops;

	ret = v4l2_subdev_init_finalize(&priv->subdev);
	if (ret)
		goto err_ctrl;

	ret = v4l2_async_register_subdev(&priv->subdev);
	if (ret)
		goto err_ctrl;

	dev_info(dev, "CSI VC Source registered!\n");
	return 0;

err_ctrl:
	v4l2_ctrl_handler_free(&priv->ctrl_handler);

err_free:
	platform_set_drvdata(pdev, NULL);
	kfree(priv);
	return ret;
}

static int csi_vc_remove(struct platform_device *pdev)
{
	struct csi_vc *priv = platform_get_drvdata(pdev);
	v4l2_ctrl_handler_free(&priv->ctrl_handler);
	return 0;
}

static const struct of_device_id csi_vc_dt_ids[] = {
	{ .compatible = "csi-vc", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, csi_vc_dt_ids);

static struct platform_driver csi_vc_driver = {
	.probe	= csi_vc_probe,
	.remove	= csi_vc_remove,
	.driver	= {
		.of_match_table = csi_vc_dt_ids,
		.name = "csi-vc",
	},
};

module_platform_driver(csi_vc_driver);

MODULE_DESCRIPTION("CSI VC source");
MODULE_AUTHOR("Michael Wu");
MODULE_LICENSE("GPL");

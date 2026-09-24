// SPDX-License-Identifier: GPL-2.0
/* Driver for the TI DP83TC812/813/814 phy */

#include <linux/bitfield.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/phy.h>

#define DP83TC812_PHY_ID	0x2000a261

#define DP83TC812_PHYRCR		0x1F
#define DP83TC812_PHYRCR_HARD_RESET	BIT(15)
#define DP83TC812_PHYRCR_SOFT_RESET	BIT(14)

#define DP83TC812_RGMII_CTRL 0x0600
#define DP83TC812_RGMII_CTRL_CFG_RGMII_EN BIT(3)

#define DP83TC812_SGMII_CTRL_1 0x0608
#define DP83TC812_SGMII_CTRL_1_CFG_SGMII_EN BIT(9)

#define DP83TC812_RMII_CTRL_1 0x0648
#define DP83TC812_RMII_CTRL_1_CFG_RMII_MODE BIT(6)

#define DP83TC812_RGMII_CLK_SHIFT_CTRL	0x0602
#define DP83TC812_RGMII_TX_CLK_DELAY_EN	BIT(0)
#define DP83TC812_RGMII_RX_CLK_DELAY_EN	BIT(1)

#define DP83TC812_DSP_REG_71		0x0871
#define DP83TC812_DSP_REG_71_SQI_WORST	GENMASK(7, 5)
#define DP83TC812_DSP_REG_71_SQI 	GENMASK(3, 1)

#define DP83TC812_SQI_MAX		7

// This is like reg_sequence in regmap, but specific to TI since it maps the most significant nibble to MMD values
struct reg_seq {
	uint16_t addr;
	uint16_t val;
};

// These values are taken from SNLA389G
const struct reg_seq master_mode_regs[] = {
	{ 0x001F, 0x8000 },  // Hard reset
	{ 0x0523, 0x0001 },  // Disable link up
	{ 0x1834, 0xC000 },  // Config phy for master mode
	{ 0x081C, 0x0FE2 },  // Interop config
	{ 0x0873, 0x0021 },
	{ 0x089E, 0x0010 },
	{ 0x0874, 0x6866 },
	{ 0x0875, 0x6868 },
	{ 0x0812, 0x00EE },
	{ 0x0816, 0x0300 },
	{ 0x0806, 0x293A },
	{ 0x0807, 0x3348 },
	{ 0x0808, 0x3D56 },
	{ 0x083E, 0x045F },
	{ 0x0834, 0x8000 },
	{ 0x0862, 0x0330 },
	{ 0x0896, 0x32CB },
	{ 0x003E, 0x0009 },
	{ 0x0848, 0x0030 },
	{ 0x0830, 0x0143 },
	{ 0x080A, 0x0015 },
	{ 0x0820, 0x03AA },
	{ 0x0826, 0x1407 },
	{ 0x083D, 0x0047 },
	{ 0x086C, 0x1336 },
	{ 0x0856, 0x1000 },
	{ 0x0842, 0xBAB8 },
	{ 0x08F3, 0x0015 },
	{ 0x08AD, 0x0019 },
	{ 0x08ED, 0x001D },
	{ 0x08EF, 0x0021 },
	{ 0x08F0, 0x0025 },
	{ 0x08F1, 0x0029 },
	{ 0x08F2, 0x002D },
	{ 0x085A, 0x3000 },  // Improve RF immunity performance
	{ 0x085B, 0x3000 },
	{ 0x0189, 0x0018 },  // TC10 Interoperability
	{ 0x018B, 0x144B },
	{ 0x0154, 0x0220 },  // Interop config
	{ 0x001F, 0x4000 },  // Soft reset
	{ 0x0523, 0x0000 },  // Enable link up
};

const struct reg_seq slave_mode_regs[] = {
	{ 0x001F, 0x8000 },  // Hard reset
	{ 0x0523, 0x0001 },  // Disable link up
	{ 0x1834, 0x8000 },  // Config phy for master mode
	{ 0x0862, 0x0330 },  // Interop config
	{ 0x086E, 0x1868 },
	{ 0x0812, 0x00F4 },
	{ 0x0816, 0x0300 },
	{ 0x0873, 0x0021 },
	{ 0x0896, 0x22FF },
	{ 0x089E, 0x0000 },
	{ 0x08F3, 0x0015 },
	{ 0x08AD, 0x0019 },
	{ 0x08ED, 0x001D },
	{ 0x08EF, 0x0021 },
	{ 0x08F0, 0x0025 },
	{ 0x08F1, 0x0029 },
	{ 0x08F2, 0x002D },
	{ 0x085A, 0x3000 },  // Improve RF immunity performance
	{ 0x085B, 0x3000 },
	{ 0x0189, 0x0018 },  // TC10 Interoperability
	{ 0x018B, 0x144B },
	{ 0x0154, 0x0220 },  // Interop config
	{ 0x001F, 0x4000 },  // Soft reset
	{ 0x0523, 0x0000 },  // Enable link up
};

static int dp83812_write_reg_seq(struct phy_device *phydev, const struct reg_seq *seq, unsigned int len)
{
	for (unsigned int i = 0; i < len; ++i) {
		const struct reg_seq *reg = &seq[i];
		const uint32_t regnum = reg->addr & 0x0FFF;
		int devad;
		int ret;
		switch (reg->addr >> 12) {
		case 0:
			devad = MDIO_MMD_VEND2;
			break;
		case 1:
			devad = MDIO_MMD_PMAPMD;
			break;
		case 3:
			devad = MDIO_MMD_PCS;
			break;
		default:
			return -EINVAL;
		}
		if (regnum < 0x20) {
			ret = phy_write(phydev, regnum, reg->val);
			if (ret)
				return ret;
			continue;
		}
		ret = phy_write_mmd(phydev, devad, regnum, reg->val);
		if (ret)
			return ret;
	}
	return 0;
}

static int dp83812_soft_reset(struct phy_device *phydev)
{
	int ret = phy_write(phydev, DP83TC812_PHYRCR, DP83TC812_PHYRCR_HARD_RESET);
	return ret < 0 ? ret : 0;
}

static int dp83812_config_init(struct phy_device *phydev)
{
	int ret;

	ret = genphy_c45_pma_baset1_read_master_slave(phydev);
	if (ret)
		return ret;

	if (phydev->master_slave_state == MASTER_SLAVE_STATE_MASTER) {
		ret = dp83812_write_reg_seq(phydev, master_mode_regs, ARRAY_SIZE(master_mode_regs));
	} else if (phydev->master_slave_state == MASTER_SLAVE_STATE_SLAVE) {
		ret = dp83812_write_reg_seq(phydev, slave_mode_regs, ARRAY_SIZE(slave_mode_regs));
	} else {
		return -EINVAL;
	}
	if (ret)
		return ret;

	phy_clear_bits_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_RGMII_CTRL,
			   DP83TC812_RGMII_CTRL_CFG_RGMII_EN);
	phy_clear_bits_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_SGMII_CTRL_1,
			   DP83TC812_SGMII_CTRL_1_CFG_SGMII_EN);
	phy_clear_bits_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_RMII_CTRL_1,
			   DP83TC812_RMII_CTRL_1_CFG_RMII_MODE);

	switch (phydev->interface) {
	case PHY_INTERFACE_MODE_MII:
		break;
	case PHY_INTERFACE_MODE_SGMII:
		phy_set_bits_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_SGMII_CTRL_1,
				 DP83TC812_SGMII_CTRL_1_CFG_SGMII_EN);
		break;
	case PHY_INTERFACE_MODE_RMII:
		phy_set_bits_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_RMII_CTRL_1,
				 DP83TC812_RMII_CTRL_1_CFG_RMII_MODE);
		break;
	case PHY_INTERFACE_MODE_RGMII:
	case PHY_INTERFACE_MODE_RGMII_ID:
	case PHY_INTERFACE_MODE_RGMII_TXID:
	case PHY_INTERFACE_MODE_RGMII_RXID:
		phy_set_bits_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_RGMII_CTRL,
				 DP83TC812_RGMII_CTRL_CFG_RGMII_EN);
		break;
	default:
		return -EINVAL;
	}

	{
		int val = phy_read_mmd(phydev, MDIO_MMD_VEND2,
				       DP83TC812_RGMII_CLK_SHIFT_CTRL);

		val &= ~(DP83TC812_RGMII_TX_CLK_DELAY_EN |
			 DP83TC812_RGMII_RX_CLK_DELAY_EN);
		if (phydev->interface == PHY_INTERFACE_MODE_RGMII_ID)
			val |= (DP83TC812_RGMII_TX_CLK_DELAY_EN |
				DP83TC812_RGMII_RX_CLK_DELAY_EN);

		if (phydev->interface == PHY_INTERFACE_MODE_RGMII_TXID)
			val |= DP83TC812_RGMII_TX_CLK_DELAY_EN;

		if (phydev->interface == PHY_INTERFACE_MODE_RGMII_RXID)
			val |= DP83TC812_RGMII_RX_CLK_DELAY_EN;

		phy_write_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_RGMII_CLK_SHIFT_CTRL, val);
	}

	phydev->autoneg = AUTONEG_DISABLE;
	phydev->speed = SPEED_100;
	phydev->duplex = DUPLEX_FULL;

	return 0;

}

static int dp83812_config_aneg(struct phy_device *phydev)
{
	int ret;

	ret = genphy_c45_pma_baset1_setup_master_slave(phydev);
	if (ret)
		return ret;

	return genphy_c45_pma_baset1_read_master_slave(phydev);
}

static int dp83812_read_status(struct phy_device *phydev)
{
	return genphy_update_link(phydev);
}

static int dp83812_get_sqi(struct phy_device *phydev)
{
	int ret;

	if (!phydev->link)
		return 0;

	ret = phy_read_mmd(phydev, MDIO_MMD_VEND2, DP83TC812_DSP_REG_71);
	if (ret < 0)
		return 0;

	return FIELD_GET(DP83TC812_DSP_REG_71_SQI, ret);
}

static int dp83812_get_sqi_max(struct phy_device *phydev)
{
        return DP83TC812_SQI_MAX;
}

static struct phy_driver dp83812_driver[] = {
	{
		PHY_ID_MATCH_MODEL(DP83TC812_PHY_ID),
		.name = "TI DP83TC812/813/814",
		.soft_reset = dp83812_soft_reset,
		.config_init = dp83812_config_init,
		.features = PHY_BASIC_T1_FEATURES,
		.suspend = genphy_suspend,
		.resume = genphy_resume,
		.config_aneg = dp83812_config_aneg,
		.read_status = dp83812_read_status,
		.get_sqi = dp83812_get_sqi,
		.get_sqi_max = dp83812_get_sqi_max,
	},
};
module_phy_driver(dp83812_driver);

static struct mdio_device_id __maybe_unused dp83812_tbl[] = {
	{ PHY_ID_MATCH_MODEL(DP83TC812_PHY_ID) },
	{ },
};
MODULE_DEVICE_TABLE(mdio, dp83812_tbl);

MODULE_DESCRIPTION("Texas Instruments DP83TC812/813/814 PHY driver");
MODULE_AUTHOR("Michael Wu <mwu.code@gmail.com>");
MODULE_LICENSE("GPL");

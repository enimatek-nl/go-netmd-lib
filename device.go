package netmd

import "github.com/enimatek-nl/gousb"

type Device struct {
	vendorId gousb.ID
	deviceId gousb.ID
	name     string
}

var (
	Devices = [...]Device{
		{vendorId: 0x04dd, deviceId: 0x7202, name: "Sharp IM-MT899H"},
		{vendorId: 0x04dd, deviceId: 0x9013, name: "Sharp IM-DR400/DR410/DR420"},
		{vendorId: 0x04dd, deviceId: 0x9014, name: "Sharp IM-DR80"},
		{vendorId: 0x054c, deviceId: 0x0034, name: "Sony PCLK-XX"},
		{vendorId: 0x054c, deviceId: 0x0036, name: "Sony"},
		{vendorId: 0x054c, deviceId: 0x0075, name: "Sony MZ-N1"},
		{vendorId: 0x054c, deviceId: 0x007c, name: "Sony"},
		{vendorId: 0x054c, deviceId: 0x0080, name: "Sony LAM-1"},
		{vendorId: 0x054c, deviceId: 0x0081, name: "Sony MDS-JB980/JE780"},
		{vendorId: 0x054c, deviceId: 0x0084, name: "Sony MZ-N505"},
		{vendorId: 0x054c, deviceId: 0x0085, name: "Sony MZ-S1"},
		{vendorId: 0x054c, deviceId: 0x0086, name: "Sony MZ-N707"},
		{vendorId: 0x054c, deviceId: 0x008e, name: "Sony CMT-C7NT"},
		{vendorId: 0x054c, deviceId: 0x0097, name: "Sony PCGA-MDN1"},
		{vendorId: 0x054c, deviceId: 0x00ad, name: "Sony CMT-L7HD"},
		{vendorId: 0x054c, deviceId: 0x00c6, name: "Sony MZ-N10"},
		{vendorId: 0x054c, deviceId: 0x00c7, name: "Sony MZ-N910"},
		{vendorId: 0x054c, deviceId: 0x00c8, name: "Sony MZ-N710/NF810"},
		{vendorId: 0x054c, deviceId: 0x00c9, name: "Sony MZ-N510/N610"},
		{vendorId: 0x054c, deviceId: 0x00ca, name: "Sony MZ-NE410/NF520D"},
		{vendorId: 0x054c, deviceId: 0x00eb, name: "Sony MZ-NE810/NE910"},
		{vendorId: 0x054c, deviceId: 0x0101, name: "Sony LAM-10"},
		{vendorId: 0x054c, deviceId: 0x0113, name: "Aiwa AM-NX1"},
		{vendorId: 0x054c, deviceId: 0x013f, name: "Sony MDS-S500"},
		{vendorId: 0x054c, deviceId: 0x014c, name: "Aiwa AM-NX9"},
		{vendorId: 0x054c, deviceId: 0x017e, name: "Sony MZ-NH1"},
		{vendorId: 0x054c, deviceId: 0x0180, name: "Sony MZ-NH3D"},
		{vendorId: 0x054c, deviceId: 0x0182, name: "Sony MZ-NH900"},
		{vendorId: 0x054c, deviceId: 0x0184, name: "Sony MZ-NH700/NH800"},
		{vendorId: 0x054c, deviceId: 0x0186, name: "Sony MZ-NH600"},
		{vendorId: 0x054c, deviceId: 0x0187, name: "Sony MZ-NH600D"},
		{vendorId: 0x054c, deviceId: 0x0188, name: "Sony MZ-N920"},
		{vendorId: 0x054c, deviceId: 0x018a, name: "Sony LAM-3"},
		{vendorId: 0x054c, deviceId: 0x01e9, name: "Sony MZ-DH10P"},
		{vendorId: 0x054c, deviceId: 0x0219, name: "Sony MZ-RH10"},
		{vendorId: 0x054c, deviceId: 0x021b, name: "Sony MZ-RH710/MZ-RH910"},
		{vendorId: 0x054c, deviceId: 0x021d, name: "Sony CMT-AH10"},
		{vendorId: 0x054c, deviceId: 0x022c, name: "Sony CMT-AH10"},
		{vendorId: 0x054c, deviceId: 0x023c, name: "Sony DS-HMD1"},
		{vendorId: 0x054c, deviceId: 0x0286, name: "Sony MZ-RH1"},
	}
)

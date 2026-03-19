package main

/*

#include <stdbool.h>
#include <stdint.h>

#define FNP_DPDK_ARGV_MAX 64
#define FNP_OTHER_ARGV_MAX 32
#define FNP_LCORE_MAX 8
#define FNP_DEVICE_MAX 8
#define FNP_DEVICE_IFADDR_MAX 8
#define FNP_ROUTE_MAX 32

typedef struct {
	int mbuf_pool_size;
	int lcores[FNP_LCORE_MAX];
	int lcores_count;
	char* app_id;
	int log_level;
	char* other_argv[FNP_OTHER_ARGV_MAX];
	int other_argv_count;
	char* argv[FNP_DPDK_ARGV_MAX];
	int argc;
} dpdk_config;

typedef struct {
	char* cidr;
	char* ip;
	char* ip_mask;
	uint32_t ip_be;
	uint32_t ip_mask_be;
} fnp_ifaddr_config;

typedef struct {
	uint16_t id;
	int32_t port;
	char* name;
	char* type;
	char* pci;
	char* mac;
	bool promiscuous;
	int nb_rx_desc;			//接收描述符数
	int nb_tx_desc;			//发送描述符数
	fnp_ifaddr_config ifaddrs[FNP_DEVICE_IFADDR_MAX];
	int ifaddr_count;
} fnp_device_config;

typedef struct {
	char* dst;
	char* via;
	char* dev;
	char* src;
	uint32_t dst_ip_be;
	uint32_t dst_mask_be;
	uint32_t via_be;
	uint32_t src_be;
} fnp_route_config;

typedef struct {
	fnp_device_config devices[FNP_DEVICE_MAX];
	int devices_count;
	fnp_route_config routes[FNP_ROUTE_MAX];
	int routes_count;
} network_config;

typedef struct{
	int lcores[FNP_LCORE_MAX];
	int lcores_count;
	int mbuf_pool_size;
	int clone_pool_size;
	int rx_pool_size;
	int tx_ring_size;		//发送环形队列大小
}worker_config;

typedef struct {
	dpdk_config dpdk;
	network_config network;
	worker_config worker;
} fnp_config;

*/
import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"strconv"
	"strings"
)

const maxDpdkArgs = 64
const maxOtherArgv = 32
const maxLcores = 8
const maxDevices = 8
const maxDeviceIfaddrs = 8
const maxRoutes = 32

type DpdkConfig struct {
	MbufPoolSize int      `yaml:"mbuf_pool_size"`
	Lcores       []int    `yaml:"lcores"`
	AppID        string   `yaml:"app_id"`
	LogLevel     int      `yaml:"log_level"`
	OtherArgv    []string `yaml:"other_argv"`
}

type DeviceConfig struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	PCI         string   `yaml:"pci"`
	MAC         string   `yaml:"mac"`
	Promiscuous bool     `yaml:"promiscuous"`
	NbRxDesc    int      `yaml:"nb_rx_desc"`
	NbTxDesc    int      `yaml:"nb_tx_desc"`
	Ifaddrs     []string `yaml:"ifaddrs"`
}

type RouteConfig struct {
	Dst string `yaml:"dst"`
	Via string `yaml:"via"`
	Dev string `yaml:"dev"`
	Src string `yaml:"src"`
}

type NetworkSection struct {
	Devices []DeviceConfig `yaml:"devices"`
	Routes  []RouteConfig  `yaml:"routes"`
}

type WorkerConfig struct {
	Lcores        []int `yaml:"lcores"`
	MbufPoolSize  int   `yaml:"mbuf_pool_size"`
	ClonePoolSize int   `yaml:"clone_pool_size"`
	RxPoolSize    int   `yaml:"rx_pool_size"`
	TxRingSize    int   `yaml:"tx_ring_size"`
}

type FnpConfig struct {
	Dpdk    DpdkConfig     `yaml:"dpdk"`
	Network NetworkSection `yaml:"network"`
	Worker  WorkerConfig   `yaml:"worker"`
}

func appendUniqueArg(args []string, arg string) []string {
	if strings.TrimSpace(arg) == "" {
		return args
	}

	for _, existing := range args {
		if existing == arg {
			return args
		}
	}

	return append(args, arg)
}

func formatLcores(lcores []int) string {
	formatted := make([]string, 0, len(lcores))
	for _, lcore := range lcores {
		formatted = append(formatted, strconv.Itoa(lcore))
	}
	return strings.Join(formatted, ",")
}

func parseIPv4CIDR(cidr string) (string, string, error) {
	ipAddr, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}

	ipv4 := ipAddr.To4()
	if ipv4 == nil {
		return "", "", fmt.Errorf("only IPv4 CIDR is supported: %s", cidr)
	}

	mask := net.IP(ipNet.Mask).String()
	if mask == "<nil>" {
		return "", "", fmt.Errorf("invalid IPv4 mask in %s", cidr)
	}

	return ipv4.String(), mask, nil
}

func parseRouteDst(dst string) (string, string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(dst))
	if trimmed == "default" {
		return "0.0.0.0", "0.0.0.0", nil
	}

	return parseIPv4CIDR(dst)
}

func ipv4StringToUint32(ip string) (C.uint32_t, error) {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ip)
	}

	// 与 C 侧 inet_aton()/iphdr->addr 的原始 u32 表示保持一致。
	return C.uint32_t(binary.LittleEndian.Uint32(parsed)), nil
}

func buildTapVdevArg(device DeviceConfig, index int) string {
	return fmt.Sprintf("--vdev=net_tap%d,iface=%s,persist", index, device.Name)
}

func buildDpdkArgs(goConf *FnpConfig) ([]string, error) {
	if len(goConf.Dpdk.Lcores) == 0 {
		return nil, errors.New("dpdk.lcores is required")
	}

	args := []string{
		"fnp",
		fmt.Sprintf("-l %s", formatLcores(goConf.Dpdk.Lcores)),
		"--proc-type=primary",
	}

	appID := goConf.Dpdk.AppID
	if appID == "" {
		appID = "fnp"
	}
	args = append(args, fmt.Sprintf("--file-prefix=%s", appID))
	args = append(args, fmt.Sprintf("--log-level=%d", goConf.Dpdk.LogLevel))

	hasPhysical := false
	hasTap := false
	for i, device := range goConf.Network.Devices {
		deviceType := strings.ToLower(strings.TrimSpace(device.Type))
		switch deviceType {
		case "", "physical":
			if strings.TrimSpace(device.PCI) == "" {
				return nil, fmt.Errorf("network.devices[%d].pci is required for physical devices", i)
			}
			hasPhysical = true
			args = append(args, "-a", device.PCI)
		case "tap":
			if strings.TrimSpace(device.Name) == "" {
				return nil, fmt.Errorf("network.devices[%d].name is required for tap devices", i)
			}
			hasTap = true
			args = append(args, buildTapVdevArg(device, i))
		default:
			return nil, fmt.Errorf("unsupported device type %q at network.devices[%d]", device.Type, i)
		}
	}

	if hasTap && !hasPhysical {
		args = appendUniqueArg(args, "--no-pci")
	}

	args = append(args, goConf.Dpdk.OtherArgv...)
	return args, nil
}

func setupDpdkArg(goConf *FnpConfig, cConf *C.dpdk_config) C.int {
	if len(goConf.Dpdk.Lcores) > maxLcores {
		fmt.Fprintf(os.Stderr, "too many dpdk.lcores: got %d, max is %d\n", len(goConf.Dpdk.Lcores), maxLcores)
		return -3
	}
	if len(goConf.Dpdk.OtherArgv) > maxOtherArgv {
		fmt.Fprintf(os.Stderr, "too many dpdk.other_argv: got %d, max is %d\n", len(goConf.Dpdk.OtherArgv), maxOtherArgv)
		return -3
	}

	cConf.mbuf_pool_size = C.int(goConf.Dpdk.MbufPoolSize)
	cConf.lcores_count = C.int(len(goConf.Dpdk.Lcores))
	for i, lcore := range goConf.Dpdk.Lcores {
		cConf.lcores[i] = C.int(lcore)
	}

	appID := goConf.Dpdk.AppID
	if appID == "" {
		appID = "fnp"
	}
	cConf.app_id = C.CString(appID)
	cConf.log_level = C.int(goConf.Dpdk.LogLevel)
	cConf.other_argv_count = C.int(len(goConf.Dpdk.OtherArgv))
	for i, arg := range goConf.Dpdk.OtherArgv {
		cConf.other_argv[i] = C.CString(arg)
	}

	args, err := buildDpdkArgs(goConf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return -3
	}

	if len(args) > maxDpdkArgs {
		fmt.Fprintf(os.Stderr, "too many dpdk args: got %d, max is %d\n", len(args), maxDpdkArgs)
		return -3
	}

	for i, arg := range args {
		cConf.argv[i] = C.CString(arg)
	}
	cConf.argc = C.int(len(args))
	return 0
}

func setupNetwork(goConf *FnpConfig, conf *C.fnp_config) C.int {
	if len(goConf.Network.Devices) > maxDevices {
		fmt.Fprintf(os.Stderr, "too many network.devices: got %d, max is %d\n", len(goConf.Network.Devices), maxDevices)
		return -4
	}
	conf.network.devices_count = C.int(len(goConf.Network.Devices))
	if len(goConf.Network.Routes) > maxRoutes {
		fmt.Fprintf(os.Stderr, "too many network.routes: got %d, max is %d\n", len(goConf.Network.Routes), maxRoutes)
		return -5
	}
	conf.network.routes_count = C.int(len(goConf.Network.Routes))

	for i, device := range goConf.Network.Devices {
		if len(device.Ifaddrs) > maxDeviceIfaddrs {
			fmt.Fprintf(os.Stderr, "too many ifaddrs on device %q: got %d, max is %d\n",
				device.Name, len(device.Ifaddrs), maxDeviceIfaddrs)
			return -6
		}

		conf.network.devices[i].id = C.uint16_t(i)
		conf.network.devices[i].name = C.CString(device.Name)
		conf.network.devices[i]._type = C.CString(device.Type)
		if strings.TrimSpace(device.PCI) != "" {
			conf.network.devices[i].pci = C.CString(device.PCI)
		}
		if strings.TrimSpace(device.MAC) != "" {
			conf.network.devices[i].mac = C.CString(device.MAC)
		}
		conf.network.devices[i].promiscuous = C.bool(device.Promiscuous)
		conf.network.devices[i].nb_rx_desc = C.int(device.NbRxDesc)
		conf.network.devices[i].nb_tx_desc = C.int(device.NbTxDesc)
		conf.network.devices[i].ifaddr_count = C.int(len(device.Ifaddrs))

		for j, cidr := range device.Ifaddrs {
			ip, mask, err := parseIPv4CIDR(cidr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid network.devices[%d].ifaddrs[%d]: %v\n", i, j, err)
				return -7
			}
			ipUint32, err := ipv4StringToUint32(ip)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid parsed IPv4 network.devices[%d].ifaddrs[%d]: %v\n", i, j, err)
				return -7
			}
			maskUint32, err := ipv4StringToUint32(mask)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid parsed IPv4 mask network.devices[%d].ifaddrs[%d]: %v\n", i, j, err)
				return -7
			}

			conf.network.devices[i].ifaddrs[j].ip = C.CString(ip)
			conf.network.devices[i].ifaddrs[j].ip_mask = C.CString(mask)
			conf.network.devices[i].ifaddrs[j].cidr = C.CString(cidr)
			conf.network.devices[i].ifaddrs[j].ip_be = ipUint32
			conf.network.devices[i].ifaddrs[j].ip_mask_be = maskUint32
		}
	}

	for i, route := range goConf.Network.Routes {
		if strings.TrimSpace(route.Dev) == "" {
			fmt.Fprintf(os.Stderr, "network.routes[%d].dev is required\n", i)
			return -7
		}

		dstIP, dstMask, err := parseRouteDst(route.Dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid network.routes[%d].dst: %v\n", i, err)
			return -7
		}
		dstIPUint32, err := ipv4StringToUint32(dstIP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid parsed route dst network.routes[%d].dst: %v\n", i, err)
			return -7
		}
		dstMaskUint32, err := ipv4StringToUint32(dstMask)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid parsed route mask network.routes[%d].dst: %v\n", i, err)
			return -7
		}

		conf.network.routes[i].dst = C.CString(route.Dst)
		conf.network.routes[i].dst_ip_be = dstIPUint32
		conf.network.routes[i].dst_mask_be = dstMaskUint32
		if strings.TrimSpace(route.Dev) != "" {
			conf.network.routes[i].dev = C.CString(route.Dev)
		}
		if strings.TrimSpace(route.Via) != "" {
			viaUint32, err := ipv4StringToUint32(route.Via)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid network.routes[%d].via: %v\n", i, err)
				return -7
			}
			conf.network.routes[i].via = C.CString(route.Via)
			conf.network.routes[i].via_be = viaUint32
		}
		if strings.TrimSpace(route.Src) != "" {
			srcUint32, err := ipv4StringToUint32(route.Src)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid network.routes[%d].src: %v\n", i, err)
				return -7
			}
			conf.network.routes[i].src = C.CString(route.Src)
			conf.network.routes[i].src_be = srcUint32
		}
	}

	return 0
}

//export parse_fnp_config
func parse_fnp_config(path *C.char, conf *C.fnp_config) C.int {
	*conf = C.fnp_config{}

	bs, err := os.ReadFile(C.GoString(path))
	if err != nil {
		return -1
	}
	goConf := FnpConfig{}
	err = yaml.Unmarshal(bs, &goConf)
	if err != nil {
		return -2
	}

	fmt.Printf("read yaml: %+v\n", goConf)

	//DPDK Config
	ret := setupDpdkArg(&goConf, &conf.dpdk)
	if ret != 0 {
		return ret
	}

	//worker Config
	if len(goConf.Worker.Lcores) > maxLcores {
		fmt.Fprintf(os.Stderr, "too many worker.lcores: got %d, max is %d\n", len(goConf.Worker.Lcores), maxLcores)
		return -4
	}

	conf.worker.mbuf_pool_size = C.int(goConf.Worker.MbufPoolSize)
	conf.worker.clone_pool_size = C.int(goConf.Worker.ClonePoolSize)
	conf.worker.rx_pool_size = C.int(goConf.Worker.RxPoolSize)
	conf.worker.tx_ring_size = C.int(goConf.Worker.TxRingSize)
	conf.worker.lcores_count = C.int(len(goConf.Worker.Lcores))
	for i, lcore := range goConf.Worker.Lcores {
		conf.worker.lcores[i] = C.int(lcore)
	}

	// Network Config
	ret = setupNetwork(&goConf, conf)
	if ret != 0 {
		return ret
	}

	return 0
}

func main() {
	path := "conf/fnp.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	fnp := C.fnp_config{}
	parse_fnp_config(C.CString(path), &fnp)
	fmt.Printf("%+v\n", fnp)
}

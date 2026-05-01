package main

/*

#include <stdbool.h>
#include <stdint.h>

#define FNP_DPDK_ARGV_MAX 64
#define FNP_OTHER_ARGV_MAX 32
#define FNP_LCORE_MAX 8
#define FNP_DEVICE_MAX 8
#define FNP_DEVICE_IFADDR_MAX 16
#define FNP_NETWORK_MAX 16
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
	uint16_t id;
	int32_t port;
	char* name;
	char* device_type;
	char* driver;
	char* pci;
	char* mac;
	bool promiscuous;
	int nb_rx_desc;			//接收描述符数
	int nb_tx_desc;			//发送描述符数
	char* ifaddrs[FNP_DEVICE_IFADDR_MAX];
	int ifaddrs_count;
} fnp_device_config;

typedef struct {
	char* dst;
	char* via;
	char* dev;
	char* src;
	int priority;
	uint32_t dst_ip_be;
	uint32_t dst_mask_be;
	uint32_t via_be;
	uint32_t src_be;
} fnp_route_config;

typedef struct {
	uint16_t id;
	char* name;
	char* device;
	char* cidr;
	char* gateway;
	int priority;
	uint32_t subnet_be;
	uint32_t netmask_be;
	uint32_t gateway_be;
} fnp_network_pool_config;

typedef struct {
	fnp_device_config devices[FNP_DEVICE_MAX];
	int devices_count;
	fnp_network_pool_config networks[FNP_NETWORK_MAX];
	int networks_count;
	fnp_route_config routes[FNP_ROUTE_MAX];
	int routes_count;
} network_config;

typedef struct{
	int lcores[FNP_LCORE_MAX];
	int lcores_count;
	int mbuf_pool_size;
	int clone_pool_size;
	int rx_pool_size;
	int worker_tx_ring_size;		//worker发送环形队列大小
}worker_config;

typedef struct {
	dpdk_config dpdk;
	network_config network;
	worker_config worker;
	int socket_rx_ring_size;
	int socket_tx_ring_size;
} fnp_config;

static inline int fnp_device_ifaddr_max(void) {
	return FNP_DEVICE_IFADDR_MAX;
}

static inline void fnp_config_set_device_ifaddr_count(fnp_config* conf, int device_index, int count) {
	conf->network.devices[device_index].ifaddrs_count = count;
}

static inline void fnp_config_set_device_ifaddr(fnp_config* conf, int device_index, int ifaddr_index, char* ifaddr) {
	conf->network.devices[device_index].ifaddrs[ifaddr_index] = ifaddr;
}

*/
import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxDpdkArgs = 64
const maxOtherArgv = 32
const maxDpdkLcores = 8   // must match C-side FNP_LCORE_MAX
const maxWorkerLcores = 4 // must match C-side FNP_MAX_WORKER_NUM
const maxDevices = 8
const maxNetworks = 16
const maxRoutes = 32
const defaultStaticRoutePriority = 100

type DpdkConfig struct {
	MbufPoolSize int      `yaml:"mbuf_pool_size"`
	Lcores       []int    `yaml:"lcores"`
	AppID        string   `yaml:"app_id"`
	LogLevel     int      `yaml:"log_level"`
	OtherArgv    []string `yaml:"other_argv"`
}

type DeviceConfig struct {
	Name          string   `yaml:"name"`
	Type          string   `yaml:"type"`
	Driver        string   `yaml:"driver"`
	PCI           string   `yaml:"pci"`
	MAC           string   `yaml:"mac"`
	Promiscuous   bool     `yaml:"promiscuous"`
	NbRxDesc      int      `yaml:"nb_rx_desc"`
	NbTxDesc      int      `yaml:"nb_tx_desc"`
	LegacyIfaddrs []string `yaml:"ifaddrs"`
}

type NetworkPoolConfig struct {
	Name     string `yaml:"name"`
	Device   string `yaml:"device"`
	CIDR     string `yaml:"cidr"`
	Subnet   string `yaml:"subnet"`
	Gateway  string `yaml:"gateway"`
	Priority *int   `yaml:"priority"`
}

type RouteConfig struct {
	Dst      string `yaml:"dst"`
	Via      string `yaml:"via"`
	Dev      string `yaml:"dev"`
	Src      string `yaml:"src"`
	Priority *int   `yaml:"priority"`
}

type NetworkSection struct {
	Devices  []DeviceConfig      `yaml:"devices"`
	Networks []NetworkPoolConfig `yaml:"networks"`
	Routes   []RouteConfig       `yaml:"routes"`
}

type WorkerConfig struct {
	Lcores            []int `yaml:"lcores"`
	MbufPoolSize      int   `yaml:"mbuf_pool_size"`
	ClonePoolSize     int   `yaml:"clone_pool_size"`
	RxPoolSize        int   `yaml:"rx_pool_size"`
	WorkerTxRingSize  int   `yaml:"worker_tx_ring_size"`
}

type FnpConfig struct {
	Dpdk             DpdkConfig     `yaml:"dpdk"`
	Network          NetworkSection `yaml:"network"`
	Worker           WorkerConfig   `yaml:"worker"`
	SocketRxRingSize int            `yaml:"socket_rx_ring_size"`
	SocketTxRingSize int            `yaml:"socket_tx_ring_size"`
}

func normalizeDeviceType(deviceType string) string {
	trimmed := strings.ToLower(strings.TrimSpace(deviceType))
	if trimmed == "" {
		return "ethernet"
	}
	return trimmed
}

func normalizeDeviceDriver(deviceDriver string, deviceType string) string {
	trimmed := strings.ToLower(strings.TrimSpace(deviceDriver))
	if trimmed == "" && deviceType == "ethernet" {
		return "physical"
	}
	return trimmed
}

func validateConfig(goConf *FnpConfig) error {
	if goConf == nil {
		return errors.New("nil config")
	}

	for i, device := range goConf.Network.Devices {
		if strings.TrimSpace(device.Name) == "" {
			return fmt.Errorf("network.devices[%d].name is required", i)
		}

		deviceType := normalizeDeviceType(device.Type)
		deviceDriver := normalizeDeviceDriver(device.Driver, deviceType)

		switch deviceType {
		case "ethernet":
			switch deviceDriver {
			case "physical":
				if strings.TrimSpace(device.PCI) == "" {
					return fmt.Errorf("network.devices[%d].pci is required for ethernet physical devices", i)
				}
			case "dpdk_tap":
				if strings.TrimSpace(device.PCI) != "" {
					return fmt.Errorf("network.devices[%d].pci is not supported for ethernet dpdk_tap devices", i)
				}
			default:
				return fmt.Errorf("unsupported device driver %q at network.devices[%d]", device.Driver, i)
			}
		case "tap", "tun":
			return fmt.Errorf("unsupported device type %q at network.devices[%d]: runtime only supports ethernet", deviceType, i)
		default:
			return fmt.Errorf("unsupported device type %q at network.devices[%d]", device.Type, i)
		}
	}

	if goConf.SocketRxRingSize == 0 {
		goConf.SocketRxRingSize = 8192
	}
	if goConf.SocketTxRingSize == 0 {
		goConf.SocketTxRingSize = 8192
	}
	if goConf.SocketRxRingSize < 2 || goConf.SocketRxRingSize&(goConf.SocketRxRingSize-1) != 0 {
		return fmt.Errorf("socket_rx_ring_size must be a power of two and at least 2")
	}
	if goConf.SocketTxRingSize < 2 || goConf.SocketTxRingSize&(goConf.SocketTxRingSize-1) != 0 {
		return fmt.Errorf("socket_tx_ring_size must be a power of two and at least 2")
	}
	if goConf.Worker.WorkerTxRingSize == 0 {
		goConf.Worker.WorkerTxRingSize = 8192
	}
	if goConf.Worker.WorkerTxRingSize < 2 || goConf.Worker.WorkerTxRingSize&(goConf.Worker.WorkerTxRingSize-1) != 0 {
		return fmt.Errorf("worker.worker_tx_ring_size must be a power of two and at least 2")
	}
	return nil
}

func decodeConfig(bs []byte) (FnpConfig, error) {
	goConf := FnpConfig{}
	decoder := yaml.NewDecoder(bytes.NewReader(bs))
	decoder.KnownFields(true)
	if err := decoder.Decode(&goConf); err != nil {
		return goConf, err
	}

	if err := validateConfig(&goConf); err != nil {
		return goConf, err
	}

	return goConf, nil
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
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}

	ipv4 := ipNet.IP.To4()
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

func pickNetworkCIDR(network NetworkPoolConfig) string {
	if strings.TrimSpace(network.CIDR) != "" {
		return network.CIDR
	}
	return network.Subnet
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
	for i, device := range goConf.Network.Devices {
		deviceType := normalizeDeviceType(device.Type)
		deviceDriver := normalizeDeviceDriver(device.Driver, deviceType)

		switch deviceType {
		case "ethernet":
			switch deviceDriver {
			case "physical":
				if strings.TrimSpace(device.PCI) == "" {
					return nil, fmt.Errorf("network.devices[%d].pci is required for ethernet physical devices", i)
				}
				hasPhysical = true
				args = append(args, "-a", device.PCI)
			case "dpdk_tap":
				if strings.TrimSpace(device.Name) == "" {
					return nil, fmt.Errorf("network.devices[%d].name is required for ethernet dpdk_tap devices", i)
				}
				args = append(args, buildTapVdevArg(device, i))
			default:
				return nil, fmt.Errorf("unsupported device driver %q at network.devices[%d]", device.Driver, i)
			}
		case "tap", "tun":
			continue
		default:
			return nil, fmt.Errorf("unsupported device type %q at network.devices[%d]", device.Type, i)
		}
	}

	if !hasPhysical {
		args = appendUniqueArg(args, "--no-pci")
	}

	args = append(args, goConf.Dpdk.OtherArgv...)
	return args, nil
}

func setupDpdkArg(goConf *FnpConfig, cConf *C.dpdk_config) C.int {
	if len(goConf.Dpdk.Lcores) > maxDpdkLcores {
		fmt.Fprintf(os.Stderr, "too many dpdk.lcores: got %d, max is %d\n", len(goConf.Dpdk.Lcores), maxDpdkLcores)
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
	if len(goConf.Network.Networks) > maxNetworks {
		fmt.Fprintf(os.Stderr, "too many network.networks: got %d, max is %d\n", len(goConf.Network.Networks), maxNetworks)
		return -6
	}
	conf.network.networks_count = C.int(len(goConf.Network.Networks))
	if len(goConf.Network.Routes) > maxRoutes {
		fmt.Fprintf(os.Stderr, "too many network.routes: got %d, max is %d\n", len(goConf.Network.Routes), maxRoutes)
		return -5
	}
	conf.network.routes_count = C.int(len(goConf.Network.Routes))

	for i, device := range goConf.Network.Devices {
		if len(device.LegacyIfaddrs) > 0 {
			maxIfaddrs := int(C.fnp_device_ifaddr_max())
			if len(device.LegacyIfaddrs) > maxIfaddrs {
				fmt.Fprintf(os.Stderr, "too many network.devices[%d].ifaddrs: got %d, max is %d\n", i, len(device.LegacyIfaddrs), maxIfaddrs)
				return -7
			}
		}

		conf.network.devices[i].id = C.uint16_t(i)
		conf.network.devices[i].name = C.CString(device.Name)
		conf.network.devices[i].device_type = C.CString(device.Type)
		if strings.TrimSpace(device.Driver) != "" {
			conf.network.devices[i].driver = C.CString(device.Driver)
		}
		if strings.TrimSpace(device.PCI) != "" {
			conf.network.devices[i].pci = C.CString(device.PCI)
		}
		if strings.TrimSpace(device.MAC) != "" {
			conf.network.devices[i].mac = C.CString(device.MAC)
		}
		conf.network.devices[i].promiscuous = C.bool(device.Promiscuous)
		conf.network.devices[i].nb_rx_desc = C.int(device.NbRxDesc)
		conf.network.devices[i].nb_tx_desc = C.int(device.NbTxDesc)
		C.fnp_config_set_device_ifaddr_count(conf, C.int(i), C.int(len(device.LegacyIfaddrs)))
		for j, ifaddr := range device.LegacyIfaddrs {
			C.fnp_config_set_device_ifaddr(conf, C.int(i), C.int(j), C.CString(ifaddr))
		}
	}

	for i, network := range goConf.Network.Networks {
		cidr := pickNetworkCIDR(network)
		if strings.TrimSpace(network.Name) == "" {
			fmt.Fprintf(os.Stderr, "network.networks[%d].name is required\n", i)
			return -7
		}
		if strings.TrimSpace(network.Device) == "" {
			fmt.Fprintf(os.Stderr, "network.networks[%d].device is required\n", i)
			return -7
		}
		if strings.TrimSpace(cidr) == "" {
			fmt.Fprintf(os.Stderr, "network.networks[%d].cidr or subnet is required\n", i)
			return -7
		}
		if strings.TrimSpace(network.Gateway) == "" {
			fmt.Fprintf(os.Stderr, "network.networks[%d].gateway is required\n", i)
			return -7
		}

		subnet, mask, err := parseIPv4CIDR(cidr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid network.networks[%d].cidr: %v\n", i, err)
			return -7
		}
		subnetUint32, err := ipv4StringToUint32(subnet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid parsed network subnet network.networks[%d].cidr: %v\n", i, err)
			return -7
		}
		maskUint32, err := ipv4StringToUint32(mask)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid parsed network mask network.networks[%d].cidr: %v\n", i, err)
			return -7
		}
		gatewayUint32, err := ipv4StringToUint32(network.Gateway)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid network.networks[%d].gateway: %v\n", i, err)
			return -7
		}

		conf.network.networks[i].id = C.uint16_t(i)
		conf.network.networks[i].name = C.CString(network.Name)
		conf.network.networks[i].device = C.CString(network.Device)
		conf.network.networks[i].cidr = C.CString(cidr)
		conf.network.networks[i].gateway = C.CString(network.Gateway)
		priority := defaultStaticRoutePriority
		if network.Priority != nil {
			priority = *network.Priority
		}
		conf.network.networks[i].priority = C.int(priority)
		conf.network.networks[i].subnet_be = subnetUint32
		conf.network.networks[i].netmask_be = maskUint32
		conf.network.networks[i].gateway_be = gatewayUint32
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
		priority := defaultStaticRoutePriority
		if route.Priority != nil {
			priority = *route.Priority
		}
		conf.network.routes[i].priority = C.int(priority)
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
	goConf, err := decodeConfig(bs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return -2
	}

	//DPDK Config
	ret := setupDpdkArg(&goConf, &conf.dpdk)
	if ret != 0 {
		return ret
	}

	//worker Config
	if len(goConf.Worker.Lcores) > maxWorkerLcores {
		fmt.Fprintf(os.Stderr, "too many worker.lcores: got %d, max is %d\n", len(goConf.Worker.Lcores), maxWorkerLcores)
		return -4
	}

	conf.worker.mbuf_pool_size = C.int(goConf.Worker.MbufPoolSize)
	conf.worker.clone_pool_size = C.int(goConf.Worker.ClonePoolSize)
	conf.worker.rx_pool_size = C.int(goConf.Worker.RxPoolSize)
	conf.worker.worker_tx_ring_size = C.int(goConf.Worker.WorkerTxRingSize)
	conf.socket_rx_ring_size = C.int(goConf.SocketRxRingSize)
	conf.socket_tx_ring_size = C.int(goConf.SocketTxRingSize)
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
	path := "k8s/conf/fnp-nic.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	fnp := C.fnp_config{}
	parse_fnp_config(C.CString(path), &fnp)
	fmt.Printf("%+v\n", fnp)
}

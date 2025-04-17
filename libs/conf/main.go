package main

/*

#include <stdbool.h>

typedef struct {
	char* argv[32];
	int argc;
} dpdk_config;

typedef struct {
	char* name;
	char* ip;
	char* ip_mask;
	char* gateway;
} network_config;

typedef struct {
	network_config networks[8];
	int networks_count;
    bool promiscuous;
	int nb_rx_desc;			//接收描述符数
	int nb_tx_desc;			//发送描述符数
} port_config;

typedef struct{
	int lcores[8];
	int lcores_count;
	int mbuf_pool_size;
	int clone_pool_size;
	int rx_pool_size;
	int tx_ring_size;		//发送环形队列大小
}worker_config;

typedef struct {
	dpdk_config dpdk;
	port_config ports[8];
	int ports_count;
	worker_config worker;
} fnp_config;

*/
import "C"
import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type DpdkConfig struct {
	Argv []string `yaml:"argv"`
}

type NetworkConfig struct {
	Name    string `yaml:"name"`
	IP      string `yaml:"ip"`
	IPMask  string `yaml:"ip_mask"`
	Gateway string `yaml:"gateway"`
}

type PortConfig struct {
	Networks    []NetworkConfig `yaml:"networks"`
	Promiscuous bool            `yaml:"promiscuous"`
	NbRxDesc    int             `yaml:"nb_rx_desc"`
	NbTxDesc    int             `yaml:"nb_tx_desc"`
}

type WorkerConfig struct {
	Lcores        []int `yaml:"lcores"`
	MbufPoolSize  int   `yaml:"mbuf_pool_size"`
	ClonePoolSize int   `yaml:"clone_pool_size"`
	RxPoolSize    int   `yaml:"rx_pool_size"`
	TxRingSize    int   `yaml:"tx_ring_size"`
}

type FnpConfig struct {
	Dpdk   DpdkConfig   `yaml:"dpdk"`
	Ports  []PortConfig `yaml:"ports"`
	Worker WorkerConfig `yaml:"worker"`
}

func setup_dpdk_arg(goConf *DpdkConfig, cConf *C.dpdk_config) {
	i := 0
	cConf.argv[i] = C.CString("fnp")
	i++

	for _, arg := range goConf.Argv {
		cConf.argv[i] = C.CString(arg)
		i++
	}
	cConf.argc = C.int(i)
}

//export parse_fnp_config
func parse_fnp_config(path *C.char, conf *C.fnp_config) C.int {
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
	setup_dpdk_arg(&goConf.Dpdk, &conf.dpdk)

	//worker Config
	conf.worker.mbuf_pool_size = C.int(goConf.Worker.MbufPoolSize)
	conf.worker.clone_pool_size = C.int(goConf.Worker.ClonePoolSize)
	conf.worker.rx_pool_size = C.int(goConf.Worker.RxPoolSize)
	conf.worker.tx_ring_size = C.int(goConf.Worker.TxRingSize)
	conf.worker.lcores_count = C.int(len(goConf.Worker.Lcores))
	for i, lcore := range goConf.Worker.Lcores {
		conf.worker.lcores[i] = C.int(lcore)
	}

	//Port Config
	conf.ports_count = C.int(len(goConf.Ports))
	for i, port := range goConf.Ports {
		// Network Config
		conf.ports[i].networks_count = C.int(len(port.Networks))
		for j, network := range port.Networks {
			conf.ports[i].networks[j].name = C.CString(network.Name)
			conf.ports[i].networks[j].ip = C.CString(network.IP)
			conf.ports[i].networks[j].ip_mask = C.CString(network.IPMask)
			conf.ports[i].networks[j].gateway = C.CString(network.Gateway)
		}
		conf.ports[i].promiscuous = C.bool(port.Promiscuous)
		conf.ports[i].nb_rx_desc = C.int(port.NbRxDesc)
		conf.ports[i].nb_tx_desc = C.int(port.NbTxDesc)
	}

	return 0
}

func main() {
	fnp := C.fnp_config{}
	parse_fnp_config(C.CString("fnp.yaml"), &fnp)
	fmt.Printf("%+v\n", fnp)
}

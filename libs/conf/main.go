package main

/*

#include <stdbool.h>

typedef struct {
	int mbuf_pool_size;
	char* argv[32];
	int argc;
} dpdk_config;


typedef struct {
	char* ip;
	char* ip_mask;
	char* gateway;
    bool promiscuous;
	int nb_rx_queue;		//接收队列数
	int nb_rx_desc;			//接收描述符数
	int nb_tx_queue;		//发送队列数
	int nb_tx_desc;			//发送描述符数
	int rx_ring_size;		//接收环形队列大小
	int tx_ring_size;		//发送环形队列大小
	int rx_mbuf_pool_size;	//用于网卡队列接收的mbuf pool大小
} port_config;

typedef struct {
	dpdk_config dpdk;
	int worker1;
	int worker2;
	port_config ports[8];
	int ports_count;
} fnp_config;

*/
import "C"
import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type DpdkConfig struct {
	MbufPoolSize int      `yaml:"mbuf_pool_size"`
	Argv         []string `yaml:"argv"`
}

type PortConfig struct {
	IP             string `yaml:"ip"`
	IPMask         string `yaml:"ip_mask"`
	Gateway        string `yaml:"gateway"`
	Promiscuous    bool   `yaml:"promiscuous"`
	NbRxQueue      int    `yaml:"nb_rx_queue"`
	NbRxDesc       int    `yaml:"nb_rx_desc"`
	NbTxQueue      int    `yaml:"nb_tx_queue"`
	NbTxDesc       int    `yaml:"nb_tx_desc"`
	RxRingSize     int    `yaml:"rx_ring_size"`
	TxRingSize     int    `yaml:"tx_ring_size"`
	RxMbufPoolSize int    `yaml:"rx_mbuf_pool_size"`
}

type FnpConfig struct {
	Dpdk    DpdkConfig   `yaml:"dpdk"`
	Ports   []PortConfig `yaml:"ports"`
	Worker1 int          `yaml:"worker1"`
	Worker2 int          `yaml:"worker2"`
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
	conf.dpdk.mbuf_pool_size = C.int(goConf.Dpdk.MbufPoolSize)

	//worker Config
	conf.worker1 = C.int(goConf.Worker1)
	conf.worker2 = C.int(goConf.Worker2)

	//Port Config
	conf.ports_count = C.int(len(goConf.Ports))
	for i, port := range goConf.Ports {
		conf.ports[i].ip = C.CString(port.IP)
		conf.ports[i].ip_mask = C.CString(port.IPMask)
		conf.ports[i].gateway = C.CString(port.Gateway)
		conf.ports[i].promiscuous = C.bool(port.Promiscuous)
		conf.ports[i].nb_rx_queue = C.int(port.NbRxQueue)
		conf.ports[i].nb_rx_desc = C.int(port.NbRxDesc)
		conf.ports[i].nb_tx_queue = C.int(port.NbTxQueue)
		conf.ports[i].nb_tx_desc = C.int(port.NbTxDesc)
		conf.ports[i].rx_ring_size = C.int(port.RxRingSize)
		conf.ports[i].tx_ring_size = C.int(port.TxRingSize)
		conf.ports[i].rx_mbuf_pool_size = C.int(port.RxMbufPoolSize)
	}

	return 0
}

func main() {
	fnp := C.fnp_config{}
	parse_fnp_config(C.CString("fnp.yaml"), &fnp)
	fmt.Printf("%+v\n", fnp)
}

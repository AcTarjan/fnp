package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeConfigRejectsUnknownField(t *testing.T) {
	_, err := decodeConfig([]byte(`
dpdk:
  mbuf_pool_size: 4096
  lcores: [2]
network:
  devices:
    - name: "eth0"
      type: "ethernet"
      driver: "physical"
      pci: "0000:03:00.0"
  unexpected: true
worker:
  lcores: [3]
  mbuf_pool_size: 4095
  clone_pool_size: 4095
  rx_pool_size: 4095
  tx_ring_size: 8192
`))
	if err == nil {
		t.Fatal("expected unknown field error, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("expected unknown field in error, got %v", err)
	}
}

func TestDecodeConfigRejectsUnsupportedTapDeviceType(t *testing.T) {
	_, err := decodeConfig([]byte(`
dpdk:
  mbuf_pool_size: 4096
  lcores: [2]
network:
  devices:
    - name: "tap0"
      type: "tap"
      driver: "physical"
worker:
  lcores: [3]
  mbuf_pool_size: 4095
  clone_pool_size: 4095
  rx_pool_size: 4095
  tx_ring_size: 8192
`))
	if err == nil {
		t.Fatal("expected unsupported tap device type error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported device type \"tap\"") {
		t.Fatalf("expected unsupported tap device type error, got %v", err)
	}
}

func TestDecodeConfigAcceptsVdevTapTemplate(t *testing.T) {
	path := filepath.Join("..", "..", "..", "k8s", "conf", "fnp-vdev-tap.yaml")
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}

	conf, err := decodeConfig(bs)
	if err != nil {
		t.Fatalf("decode template: %v", err)
	}
	if len(conf.Network.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(conf.Network.Devices))
	}
	if len(conf.Network.Routes) != 0 {
		t.Fatalf("expected 0 routes, got %d", len(conf.Network.Routes))
	}
}

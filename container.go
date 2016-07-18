// Copyright 2015 go-dockerclient authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package docker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-units"
)

// ErrContainerAlreadyExists is the error returned by CreateContainer when the
// container already exists.
var ErrContainerAlreadyExists = errors.New("container already exists")

// ListContainersOptions specify parameters to the ListContainers function.
//
// See https://goo.gl/47a6tO for more details.
type ListContainersOptions struct {
	All     bool
	Size    bool
	Limit   int
	Since   string
	Before  string
	Filters map[string][]string
}

// APIPort is a type that represents a port mapping returned by the Docker API
type APIPort struct {
	PrivatePort int64  `json:"PrivatePort,omitempty" yaml:"PrivatePort,omitempty"`
	PublicPort  int64  `json:"PublicPort,omitempty" yaml:"PublicPort,omitempty"`
	Type        string `json:"Type,omitempty" yaml:"Type,omitempty"`
	IP          string `json:"IP,omitempty" yaml:"IP,omitempty"`
}

// APIMount represents a mount point for a container.
type APIMount struct {
	Name        string `json:"Name,omitempty" yaml:"Name,omitempty"`
	Source      string `json:"Source,omitempty" yaml:"Source,omitempty"`
	Destination string `json:"Destination,omitempty" yaml:"Destination,omitempty"`
	Driver      string `json:"Driver,omitempty" yaml:"Driver,omitempty"`
	Mode        string `json:"Mode,omitempty" yaml:"Mode,omitempty"`
	RW          bool   `json:"RW,omitempty" yaml:"RW,omitempty"`
	Propogation string `json:"Propogation,omitempty" yaml:"Propogation,omitempty"`
}

// APIContainers represents each container in the list returned by
// ListContainers.
type APIContainers struct {
	ID         string            `json:"Id" yaml:"Id"`
	Image      string            `json:"Image,omitempty" yaml:"Image,omitempty"`
	Command    string            `json:"Command,omitempty" yaml:"Command,omitempty"`
	Created    int64             `json:"Created,omitempty" yaml:"Created,omitempty"`
	State      string            `json:"State,omitempty" yaml:"State,omitempty"`
	Status     string            `json:"Status,omitempty" yaml:"Status,omitempty"`
	Ports      []APIPort         `json:"Ports,omitempty" yaml:"Ports,omitempty"`
	SizeRw     int64             `json:"SizeRw,omitempty" yaml:"SizeRw,omitempty"`
	SizeRootFs int64             `json:"SizeRootFs,omitempty" yaml:"SizeRootFs,omitempty"`
	Names      []string          `json:"Names,omitempty" yaml:"Names,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty" yaml:"Labels,omitempty"`
	Networks   NetworkList       `json:"NetworkSettings,omitempty" yaml:"NetworkSettings,omitempty"`
	Mounts     []APIMount        `json:"Mounts,omitempty" yaml:"Mounts,omitempty"`
}

// NetworkList encapsulates a map of networks, as returned by the Docker API in
// ListContainers.
type NetworkList struct {
	Networks map[string]ContainerNetwork `json:"Networks" yaml:"Networks,omitempty"`
}

// ListContainers returns a slice of containers matching the given criteria.
//
// See https://goo.gl/47a6tO for more details.
func (c *Client) ListContainers(opts ListContainersOptions) ([]APIContainers, error) {
	path := "/containers/json?" + queryString(opts)
	resp, err := c.do("GET", path, doOptions{})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var containers []APIContainers
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, err
	}
	return containers, nil
}

// Port represents the port number and the protocol, in the form
// <number>/<protocol>. For example: 80/tcp.
type Port string

// Port returns the number of the port.
func (p Port) Port() string {
	return strings.Split(string(p), "/")[0]
}

// Proto returns the name of the protocol.
func (p Port) Proto() string {
	parts := strings.Split(string(p), "/")
	if len(parts) == 1 {
		return "tcp"
	}
	return parts[1]
}

// State represents the state of a container.
type State struct {
	Status            string    `json:"Status,omitempty" yaml:"Status,omitempty"`
	Running           bool      `json:"Running,omitempty" yaml:"Running,omitempty"`
	Paused            bool      `json:"Paused,omitempty" yaml:"Paused,omitempty"`
	Restarting        bool      `json:"Restarting,omitempty" yaml:"Restarting,omitempty"`
	OOMKilled         bool      `json:"OOMKilled,omitempty" yaml:"OOMKilled,omitempty"`
	RemovalInProgress bool      `json:"RemovalInProgress,omitempty" yaml:"RemovalInProgress,omitempty"`
	Dead              bool      `json:"Dead,omitempty" yaml:"Dead,omitempty"`
	Pid               int       `json:"Pid,omitempty" yaml:"Pid,omitempty"`
	ExitCode          int       `json:"ExitCode,omitempty" yaml:"ExitCode,omitempty"`
	Error             string    `json:"Error,omitempty" yaml:"Error,omitempty"`
	StartedAt         time.Time `json:"StartedAt,omitempty" yaml:"StartedAt,omitempty"`
	FinishedAt        time.Time `json:"FinishedAt,omitempty" yaml:"FinishedAt,omitempty"`
}

// String returns a human-readable description of the state
func (s *State) String() string {
	if s.Running {
		if s.Paused {
			return fmt.Sprintf("Up %s (Paused)", units.HumanDuration(time.Now().UTC().Sub(s.StartedAt)))
		}
		if s.Restarting {
			return fmt.Sprintf("Restarting (%d) %s ago", s.ExitCode, units.HumanDuration(time.Now().UTC().Sub(s.FinishedAt)))
		}

		return fmt.Sprintf("Up %s", units.HumanDuration(time.Now().UTC().Sub(s.StartedAt)))
	}

	if s.RemovalInProgress {
		return "Removal In Progress"
	}

	if s.Dead {
		return "Dead"
	}

	if s.StartedAt.IsZero() {
		return "Created"
	}

	if s.FinishedAt.IsZero() {
		return ""
	}

	return fmt.Sprintf("Exited (%d) %s ago", s.ExitCode, units.HumanDuration(time.Now().UTC().Sub(s.FinishedAt)))
}

// StateString returns a single string to describe state
func (s *State) StateString() string {
	if s.Running {
		if s.Paused {
			return "paused"
		}
		if s.Restarting {
			return "restarting"
		}
		return "running"
	}

	if s.Dead {
		return "dead"
	}

	if s.StartedAt.IsZero() {
		return "created"
	}

	return "exited"
}

// PortBinding represents the host/container port mapping as returned in the
// `docker inspect` json
type PortBinding struct {
	HostIP   string `json:"HostIP,omitempty" yaml:"HostIP,omitempty"`
	HostPort string `json:"HostPort,omitempty" yaml:"HostPort,omitempty"`
}

// PortMapping represents a deprecated field in the `docker inspect` output,
// and its value as found in NetworkSettings should always be nil
type PortMapping map[string]string

// ContainerNetwork represents the networking settings of a container per network.
type ContainerNetwork struct {
	MacAddress          string `json:"MacAddress,omitempty" yaml:"MacAddress,omitempty"`
	GlobalIPv6PrefixLen int    `json:"GlobalIPv6PrefixLen,omitempty" yaml:"GlobalIPv6PrefixLen,omitempty"`
	GlobalIPv6Address   string `json:"GlobalIPv6Address,omitempty" yaml:"GlobalIPv6Address,omitempty"`
	IPv6Gateway         string `json:"IPv6Gateway,omitempty" yaml:"IPv6Gateway,omitempty"`
	IPPrefixLen         int    `json:"IPPrefixLen,omitempty" yaml:"IPPrefixLen,omitempty"`
	IPAddress           string `json:"IPAddress,omitempty" yaml:"IPAddress,omitempty"`
	Gateway             string `json:"Gateway,omitempty" yaml:"Gateway,omitempty"`
	EndpointID          string `json:"EndpointID,omitempty" yaml:"EndpointID,omitempty"`
	NetworkID           string `json:"NetworkID,omitempty" yaml:"NetworkID,omitempty"`
}

// NetworkSettings contains network-related information about a container
type NetworkSettings struct {
	Networks               map[string]ContainerNetwork `json:"Networks,omitempty" yaml:"Networks,omitempty"`
	IPAddress              string                      `json:"IPAddress,omitempty" yaml:"IPAddress,omitempty"`
	IPPrefixLen            int                         `json:"IPPrefixLen,omitempty" yaml:"IPPrefixLen,omitempty"`
	MacAddress             string                      `json:"MacAddress,omitempty" yaml:"MacAddress,omitempty"`
	Gateway                string                      `json:"Gateway,omitempty" yaml:"Gateway,omitempty"`
	Bridge                 string                      `json:"Bridge,omitempty" yaml:"Bridge,omitempty"`
	PortMapping            map[string]PortMapping      `json:"PortMapping,omitempty" yaml:"PortMapping,omitempty"`
	Ports                  map[Port][]PortBinding      `json:"Ports,omitempty" yaml:"Ports,omitempty"`
	NetworkID              string                      `json:"NetworkID,omitempty" yaml:"NetworkID,omitempty"`
	EndpointID             string                      `json:"EndpointID,omitempty" yaml:"EndpointID,omitempty"`
	SandboxKey             string                      `json:"SandboxKey,omitempty" yaml:"SandboxKey,omitempty"`
	GlobalIPv6Address      string                      `json:"GlobalIPv6Address,omitempty" yaml:"GlobalIPv6Address,omitempty"`
	GlobalIPv6PrefixLen    int                         `json:"GlobalIPv6PrefixLen,omitempty" yaml:"GlobalIPv6PrefixLen,omitempty"`
	IPv6Gateway            string                      `json:"IPv6Gateway,omitempty" yaml:"IPv6Gateway,omitempty"`
	LinkLocalIPv6Address   string                      `json:"LinkLocalIPv6Address,omitempty" yaml:"LinkLocalIPv6Address,omitempty"`
	LinkLocalIPv6PrefixLen int                         `json:"LinkLocalIPv6PrefixLen,omitempty" yaml:"LinkLocalIPv6PrefixLen,omitempty"`
	SecondaryIPAddresses   []string                    `json:"SecondaryIPAddresses,omitempty" yaml:"SecondaryIPAddresses,omitempty"`
	SecondaryIPv6Addresses []string                    `json:"SecondaryIPv6Addresses,omitempty" yaml:"SecondaryIPv6Addresses,omitempty"`
}

// PortMappingAPI translates the port mappings as contained in NetworkSettings
// into the format in which they would appear when returned by the API
func (settings *NetworkSettings) PortMappingAPI() []APIPort {
	var mapping []APIPort
	for port, bindings := range settings.Ports {
		p, _ := parsePort(port.Port())
		if len(bindings) == 0 {
			mapping = append(mapping, APIPort{
				PrivatePort: int64(p),
				Type:        port.Proto(),
			})
			continue
		}
		for _, binding := range bindings {
			p, _ := parsePort(port.Port())
			h, _ := parsePort(binding.HostPort)
			mapping = append(mapping, APIPort{
				PrivatePort: int64(p),
				PublicPort:  int64(h),
				Type:        port.Proto(),
				IP:          binding.HostIP,
			})
		}
	}
	return mapping
}

func parsePort(rawPort string) (int, error) {
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		return 0, err
	}
	return int(port), nil
}

// Config is the list of configuration options used when creating a container.
// Config does not contain the options that are specific to starting a container on a
// given host.  Those are contained in HostConfig
type Config struct {
	Hostname          string              `json:"Hostname,omitempty" yaml:"Hostname,omitempty"`
	Domainname        string              `json:"Domainname,omitempty" yaml:"Domainname,omitempty"`
	User              string              `json:"User,omitempty" yaml:"User,omitempty"`
	Memory            int64               `json:"Memory,omitempty" yaml:"Memory,omitempty"`
	MemorySwap        int64               `json:"MemorySwap,omitempty" yaml:"MemorySwap,omitempty"`
	MemoryReservation int64               `json:"MemoryReservation,omitempty" yaml:"MemoryReservation,omitempty"`
	KernelMemory      int64               `json:"KernelMemory,omitempty" yaml:"KernelMemory,omitempty"`
	CPUShares         int64               `json:"CpuShares,omitempty" yaml:"CpuShares,omitempty"`
	CPUSet            string              `json:"Cpuset,omitempty" yaml:"Cpuset,omitempty"`
	AttachStdin       bool                `json:"AttachStdin,omitempty" yaml:"AttachStdin,omitempty"`
	AttachStdout      bool                `json:"AttachStdout,omitempty" yaml:"AttachStdout,omitempty"`
	AttachStderr      bool                `json:"AttachStderr,omitempty" yaml:"AttachStderr,omitempty"`
	PortSpecs         []string            `json:"PortSpecs,omitempty" yaml:"PortSpecs,omitempty"`
	ExposedPorts      map[Port]struct{}   `json:"ExposedPorts,omitempty" yaml:"ExposedPorts,omitempty"`
	PublishService    string              `json:"PublishService,omitempty" yaml:"PublishService,omitempty"`
	ArgsEscaped       bool                `json:"ArgsEscaped,omitempty" yaml:"ArgsEscaped,omitempty"`
	StopSignal        string              `json:"StopSignal,omitempty" yaml:"StopSignal,omitempty"`
	Tty               bool                `json:"Tty,omitempty" yaml:"Tty,omitempty"`
	OpenStdin         bool                `json:"OpenStdin,omitempty" yaml:"OpenStdin,omitempty"`
	StdinOnce         bool                `json:"StdinOnce,omitempty" yaml:"StdinOnce,omitempty"`
	Env               []string            `json:"Env,omitempty" yaml:"Env,omitempty"`
	Cmd               []string            `json:"Cmd" yaml:"Cmd"`
	DNS               []string            `json:"Dns,omitempty" yaml:"Dns,omitempty"` // For Docker API v1.9 and below only
	Image             string              `json:"Image,omitempty" yaml:"Image,omitempty"`
	Volumes           map[string]struct{} `json:"Volumes,omitempty" yaml:"Volumes,omitempty"`
	VolumeDriver      string              `json:"VolumeDriver,omitempty" yaml:"VolumeDriver,omitempty"`
	VolumesFrom       string              `json:"VolumesFrom,omitempty" yaml:"VolumesFrom,omitempty"`
	WorkingDir        string              `json:"WorkingDir,omitempty" yaml:"WorkingDir,omitempty"`
	MacAddress        string              `json:"MacAddress,omitempty" yaml:"MacAddress,omitempty"`
	Entrypoint        []string            `json:"Entrypoint" yaml:"Entrypoint"`
	NetworkDisabled   bool                `json:"NetworkDisabled,omitempty" yaml:"NetworkDisabled,omitempty"`
	SecurityOpts      []string            `json:"SecurityOpts,omitempty" yaml:"SecurityOpts,omitempty"`
	OnBuild           []string            `json:"OnBuild,omitempty" yaml:"OnBuild,omitempty"`
	Mounts            []Mount             `json:"Mounts,omitempty" yaml:"Mounts,omitempty"`
	Labels            map[string]string   `json:"Labels,omitempty" yaml:"Labels,omitempty"`
}

// Mount represents a mount point in the container.
//
// It has been added in the version 1.20 of the Docker API, available since
// Docker 1.8.
type Mount struct {
	Name        string
	Source      string
	Destination string
	Driver      string
	Mode        string
	RW          bool
}

// LogConfig defines the log driver type and the configuration for it.
type LogConfig struct {
	Type   string            `json:"Type,omitempty" yaml:"Type,omitempty"`
	Config map[string]string `json:"Config,omitempty" yaml:"Config,omitempty"`
}

// ULimit defines system-wide resource limitations
// This can help a lot in system administration, e.g. when a user starts too many processes and therefore makes the system unresponsive for other users.
type ULimit struct {
	Name string `json:"Name,omitempty" yaml:"Name,omitempty"`
	Soft int64  `json:"Soft,omitempty" yaml:"Soft,omitempty"`
	Hard int64  `json:"Hard,omitempty" yaml:"Hard,omitempty"`
}

// SwarmNode containers information about which Swarm node the container is on
type SwarmNode struct {
	ID     string            `json:"ID,omitempty" yaml:"ID,omitempty"`
	IP     string            `json:"IP,omitempty" yaml:"IP,omitempty"`
	Addr   string            `json:"Addr,omitempty" yaml:"Addr,omitempty"`
	Name   string            `json:"Name,omitempty" yaml:"Name,omitempty"`
	CPUs   int64             `json:"CPUs,omitempty" yaml:"CPUs,omitempty"`
	Memory int64             `json:"Memory,omitempty" yaml:"Memory,omitempty"`
	Labels map[string]string `json:"Labels,omitempty" yaml:"Labels,omitempty"`
}

// GraphDriver contains information about the GraphDriver used by the container
type GraphDriver struct {
	Name string            `json:"Name,omitempty" yaml:"Name,omitempty"`
	Data map[string]string `json:"Data,omitempty" yaml:"Data,omitempty"`
}

// Container is the type encompasing everything about a container - its config,
// hostconfig, etc.
type Container struct {
	ID string `json:"Id" yaml:"Id"`

	Created time.Time `json:"Created,omitempty" yaml:"Created,omitempty"`

	Path string   `json:"Path,omitempty" yaml:"Path,omitempty"`
	Args []string `json:"Args,omitempty" yaml:"Args,omitempty"`

	Config *Config `json:"Config,omitempty" yaml:"Config,omitempty"`
	State  State   `json:"State,omitempty" yaml:"State,omitempty"`
	Image  string  `json:"Image,omitempty" yaml:"Image,omitempty"`

	Node *SwarmNode `json:"Node,omitempty" yaml:"Node,omitempty"`

	NetworkSettings *NetworkSettings `json:"NetworkSettings,omitempty" yaml:"NetworkSettings,omitempty"`

	SysInitPath    string  `json:"SysInitPath,omitempty" yaml:"SysInitPath,omitempty"`
	ResolvConfPath string  `json:"ResolvConfPath,omitempty" yaml:"ResolvConfPath,omitempty"`
	HostnamePath   string  `json:"HostnamePath,omitempty" yaml:"HostnamePath,omitempty"`
	HostsPath      string  `json:"HostsPath,omitempty" yaml:"HostsPath,omitempty"`
	LogPath        string  `json:"LogPath,omitempty" yaml:"LogPath,omitempty"`
	Name           string  `json:"Name,omitempty" yaml:"Name,omitempty"`
	Driver         string  `json:"Driver,omitempty" yaml:"Driver,omitempty"`
	Mounts         []Mount `json:"Mounts,omitempty" yaml:"Mounts,omitempty"`

	Volumes     map[string]string `json:"Volumes,omitempty" yaml:"Volumes,omitempty"`
	VolumesRW   map[string]bool   `json:"VolumesRW,omitempty" yaml:"VolumesRW,omitempty"`
	HostConfig  *HostConfig       `json:"HostConfig,omitempty" yaml:"HostConfig,omitempty"`
	ExecIDs     []string          `json:"ExecIDs,omitempty" yaml:"ExecIDs,omitempty"`
	GraphDriver *GraphDriver      `json:"GraphDriver,omitempty" yaml:"GraphDriver,omitempty"`

	RestartCount int `json:"RestartCount,omitempty" yaml:"RestartCount,omitempty"`

	AppArmorProfile string `json:"AppArmorProfile,omitempty" yaml:"AppArmorProfile,omitempty"`
}

// UpdateContainerOptions specify parameters to the UpdateContainer function.
//
// See https://goo.gl/Y6fXUy for more details.
type UpdateContainerOptions struct {
	BlkioWeight       int           `json:"BlkioWeight"`
	CPUShares         int           `json:"CpuShares"`
	CPUPeriod         int           `json:"CpuPeriod"`
	CPUQuota          int           `json:"CpuQuota"`
	CpusetCpus        string        `json:"CpusetCpus"`
	CpusetMems        string        `json:"CpusetMems"`
	Memory            int           `json:"Memory"`
	MemorySwap        int           `json:"MemorySwap"`
	MemoryReservation int           `json:"MemoryReservation"`
	KernelMemory      int           `json:"KernelMemory"`
	RestartPolicy     RestartPolicy `json:"RestartPolicy,omitempty"`
}

// UpdateContainer updates the container at ID with the options
//
// See https://goo.gl/Y6fXUy for more details.
func (c *Client) UpdateContainer(id string, opts UpdateContainerOptions) error {
	resp, err := c.do("POST", fmt.Sprintf("/containers/"+id+"/update"), doOptions{data: opts, forceJSON: true})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// RenameContainerOptions specify parameters to the RenameContainer function.
//
// See https://goo.gl/laSOIy for more details.
type RenameContainerOptions struct {
	// ID of container to rename
	ID string `qs:"-"`

	// New name
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
}

// RenameContainer updates and existing containers name
//
// See https://goo.gl/laSOIy for more details.
func (c *Client) RenameContainer(opts RenameContainerOptions) error {
	resp, err := c.do("POST", fmt.Sprintf("/containers/"+opts.ID+"/rename?%s", queryString(opts)), doOptions{})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// InspectContainer returns information about a container by its ID.
//
// See https://goo.gl/RdIq0b for more details.
func (c *Client) InspectContainer(id string) (*Container, error) {
	path := "/containers/" + id + "/json"
	resp, err := c.do("GET", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return nil, &NoSuchContainer{ID: id}
		}
		return nil, err
	}
	defer resp.Body.Close()
	var container Container
	if err := json.NewDecoder(resp.Body).Decode(&container); err != nil {
		return nil, err
	}
	return &container, nil
}

// ContainerChanges returns changes in the filesystem of the given container.
//
// See https://goo.gl/9GsTIF for more details.
func (c *Client) ContainerChanges(id string) ([]Change, error) {
	path := "/containers/" + id + "/changes"
	resp, err := c.do("GET", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return nil, &NoSuchContainer{ID: id}
		}
		return nil, err
	}
	defer resp.Body.Close()
	var changes []Change
	if err := json.NewDecoder(resp.Body).Decode(&changes); err != nil {
		return nil, err
	}
	return changes, nil
}

// CreateContainerOptions specify parameters to the CreateContainer function.
//
// See https://goo.gl/WxQzrr for more details.
type CreateContainerOptions struct {
	Name             string
	Config           *Config           `qs:"-"`
	HostConfig       *HostConfig       `qs:"-"`
	NetworkingConfig *NetworkingConfig `qs:"-"`
}

// CreateContainer creates a new container, returning the container instance,
// or an error in case of failure.
//
// See https://goo.gl/WxQzrr for more details.
func (c *Client) CreateContainer(opts CreateContainerOptions) (*Container, error) {
	path := "/containers/create?" + queryString(opts)
	resp, err := c.do(
		"POST",
		path,
		doOptions{
			data: struct {
				*Config
				HostConfig       *HostConfig       `json:"HostConfig,omitempty" yaml:"HostConfig,omitempty"`
				NetworkingConfig *NetworkingConfig `json:"NetworkingConfig,omitempty" yaml:"NetworkingConfig,omitempty"`
			}{
				opts.Config,
				opts.HostConfig,
				opts.NetworkingConfig,
			},
		},
	)

	if e, ok := err.(*Error); ok {
		if e.Status == http.StatusNotFound {
			return nil, ErrNoSuchImage
		}
		if e.Status == http.StatusConflict {
			return nil, ErrContainerAlreadyExists
		}
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var container Container
	if err := json.NewDecoder(resp.Body).Decode(&container); err != nil {
		return nil, err
	}

	container.Name = opts.Name

	return &container, nil
}

// KeyValuePair is a type for generic key/value pairs as used in the Lxc
// configuration
type KeyValuePair struct {
	Key   string `json:"Key,omitempty" yaml:"Key,omitempty"`
	Value string `json:"Value,omitempty" yaml:"Value,omitempty"`
}

// RestartPolicy represents the policy for automatically restarting a container.
//
// Possible values are:
//
//   - always: the docker daemon will always restart the container
//   - on-failure: the docker daemon will restart the container on failures, at
//                 most MaximumRetryCount times
//   - unless-stopped: the docker daemon will always restart the container except
//                 when user has manually stopped the container
//   - no: the docker daemon will not restart the container automatically
type RestartPolicy struct {
	Name              string `json:"Name,omitempty" yaml:"Name,omitempty"`
	MaximumRetryCount int    `json:"MaximumRetryCount,omitempty" yaml:"MaximumRetryCount,omitempty"`
}

// AlwaysRestart returns a restart policy that tells the Docker daemon to
// always restart the container.
func AlwaysRestart() RestartPolicy {
	return RestartPolicy{Name: "always"}
}

// RestartOnFailure returns a restart policy that tells the Docker daemon to
// restart the container on failures, trying at most maxRetry times.
func RestartOnFailure(maxRetry int) RestartPolicy {
	return RestartPolicy{Name: "on-failure", MaximumRetryCount: maxRetry}
}

// RestartUnlessStopped returns a restart policy that tells the Docker daemon to
// always restart the container except when user has manually stopped the container.
func RestartUnlessStopped() RestartPolicy {
	return RestartPolicy{Name: "unless-stopped"}
}

// NeverRestart returns a restart policy that tells the Docker daemon to never
// restart the container on failures.
func NeverRestart() RestartPolicy {
	return RestartPolicy{Name: "no"}
}

// Device represents a device mapping between the Docker host and the
// container.
type Device struct {
	PathOnHost        string `json:"PathOnHost,omitempty" yaml:"PathOnHost,omitempty"`
	PathInContainer   string `json:"PathInContainer,omitempty" yaml:"PathInContainer,omitempty"`
	CgroupPermissions string `json:"CgroupPermissions,omitempty" yaml:"CgroupPermissions,omitempty"`
}

// BlockWeight represents a relative device weight for an individual device inside
// of a container
//
// See https://goo.gl/FSdP0H for more details.
type BlockWeight struct {
	Path   string `json:"Path,omitempty"`
	Weight string `json:"Weight,omitempty"`
}

// BlockLimit represents a read/write limit in IOPS or Bandwidth for a device
// inside of a container
//
// See https://goo.gl/FSdP0H for more details.
type BlockLimit struct {
	Path string `json:"Path,omitempty"`
	Rate string `json:"Rate,omitempty"`
}

// HostConfig contains the container options related to starting a container on
// a given host
type HostConfig struct {
	Binds                []string               `json:"Binds,omitempty" yaml:"Binds,omitempty"`
	CapAdd               []string               `json:"CapAdd,omitempty" yaml:"CapAdd,omitempty"`
	CapDrop              []string               `json:"CapDrop,omitempty" yaml:"CapDrop,omitempty"`
	GroupAdd             []string               `json:"GroupAdd,omitempty" yaml:"GroupAdd,omitempty"`
	ContainerIDFile      string                 `json:"ContainerIDFile,omitempty" yaml:"ContainerIDFile,omitempty"`
	LxcConf              []KeyValuePair         `json:"LxcConf,omitempty" yaml:"LxcConf,omitempty"`
	Privileged           bool                   `json:"Privileged,omitempty" yaml:"Privileged,omitempty"`
	PortBindings         map[Port][]PortBinding `json:"PortBindings,omitempty" yaml:"PortBindings,omitempty"`
	Links                []string               `json:"Links,omitempty" yaml:"Links,omitempty"`
	PublishAllPorts      bool                   `json:"PublishAllPorts,omitempty" yaml:"PublishAllPorts,omitempty"`
	DNS                  []string               `json:"Dns,omitempty" yaml:"Dns,omitempty"` // For Docker API v1.10 and above only
	DNSOptions           []string               `json:"DnsOptions,omitempty" yaml:"DnsOptions,omitempty"`
	DNSSearch            []string               `json:"DnsSearch,omitempty" yaml:"DnsSearch,omitempty"`
	ExtraHosts           []string               `json:"ExtraHosts,omitempty" yaml:"ExtraHosts,omitempty"`
	VolumesFrom          []string               `json:"VolumesFrom,omitempty" yaml:"VolumesFrom,omitempty"`
	UsernsMode           string                 `json:"UsernsMode,omitempty" yaml:"UsernsMode,omitempty"`
	NetworkMode          string                 `json:"NetworkMode,omitempty" yaml:"NetworkMode,omitempty"`
	IpcMode              string                 `json:"IpcMode,omitempty" yaml:"IpcMode,omitempty"`
	PidMode              string                 `json:"PidMode,omitempty" yaml:"PidMode,omitempty"`
	UTSMode              string                 `json:"UTSMode,omitempty" yaml:"UTSMode,omitempty"`
	RestartPolicy        RestartPolicy          `json:"RestartPolicy,omitempty" yaml:"RestartPolicy,omitempty"`
	Devices              []Device               `json:"Devices,omitempty" yaml:"Devices,omitempty"`
	LogConfig            LogConfig              `json:"LogConfig,omitempty" yaml:"LogConfig,omitempty"`
	ReadonlyRootfs       bool                   `json:"ReadonlyRootfs,omitempty" yaml:"ReadonlyRootfs,omitempty"`
	SecurityOpt          []string               `json:"SecurityOpt,omitempty" yaml:"SecurityOpt,omitempty"`
	Cgroup               string                 `json:"Cgroup,omitempty" yaml:"Cgroup,omitempty"`
	CgroupParent         string                 `json:"CgroupParent,omitempty" yaml:"CgroupParent,omitempty"`
	Memory               int64                  `json:"Memory,omitempty" yaml:"Memory,omitempty"`
	MemoryReservation    int64                  `json:"MemoryReservation,omitempty" yaml:"MemoryReservation,omitempty"`
	KernelMemory         int64                  `json:"KernelMemory,omitempty" yaml:"KernelMemory,omitempty"`
	MemorySwap           int64                  `json:"MemorySwap,omitempty" yaml:"MemorySwap,omitempty"`
	MemorySwappiness     int64                  `json:"MemorySwappiness,omitempty" yaml:"MemorySwappiness,omitempty"`
	OOMKillDisable       bool                   `json:"OomKillDisable,omitempty" yaml:"OomKillDisable,omitempty"`
	CPUShares            int64                  `json:"CpuShares,omitempty" yaml:"CpuShares,omitempty"`
	CPUSet               string                 `json:"Cpuset,omitempty" yaml:"Cpuset,omitempty"`
	CPUSetCPUs           string                 `json:"CpusetCpus,omitempty" yaml:"CpusetCpus,omitempty"`
	CPUSetMEMs           string                 `json:"CpusetMems,omitempty" yaml:"CpusetMems,omitempty"`
	CPUQuota             int64                  `json:"CpuQuota,omitempty" yaml:"CpuQuota,omitempty"`
	CPUPeriod            int64                  `json:"CpuPeriod,omitempty" yaml:"CpuPeriod,omitempty"`
	BlkioWeight          int64                  `json:"BlkioWeight,omitempty" yaml:"BlkioWeight,omitempty"`
	BlkioWeightDevice    []BlockWeight          `json:"BlkioWeightDevice,omitempty" yaml:"BlkioWeightDevice,omitempty"`
	BlkioDeviceReadBps   []BlockLimit           `json:"BlkioDeviceReadBps,omitempty" yaml:"BlkioDeviceReadBps,omitempty"`
	BlkioDeviceReadIOps  []BlockLimit           `json:"BlkioDeviceReadIOps,omitempty" yaml:"BlkioDeviceReadIOps,omitempty"`
	BlkioDeviceWriteBps  []BlockLimit           `json:"BlkioDeviceWriteBps,omitempty" yaml:"BlkioDeviceWriteBps,omitempty"`
	BlkioDeviceWriteIOps []BlockLimit           `json:"BlkioDeviceWriteIOps,omitempty" yaml:"BlkioDeviceWriteIOps,omitempty"`
	Ulimits              []ULimit               `json:"Ulimits,omitempty" yaml:"Ulimits,omitempty"`
	VolumeDriver         string                 `json:"VolumeDriver,omitempty" yaml:"VolumeDriver,omitempty"`
	OomScoreAdj          int                    `json:"OomScoreAdj,omitempty" yaml:"OomScoreAdj,omitempty"`
	PidsLimit            int64                  `json:"PidsLimit,omitempty" yaml:"PidsLimit,omitempty"`
	ShmSize              int64                  `json:"ShmSize,omitempty" yaml:"ShmSize,omitempty"`
	Tmpfs                map[string]string      `json:"Tmpfs,omitempty" yaml:"Tmpfs,omitempty"`
	AutoRemove           bool                   `json:"AutoRemove,omitempty" yaml:"AutoRemove,omitempty"`
	StorageOpt           map[string]string      `json:"StorageOpt,omitempty" yaml:"StorageOpt,omitempty"`
	Sysctls              map[string]string      `json:"Sysctls,omitempty" yaml:"Sysctls,omitempty"`
}

// NetworkingConfig represents the container's networking configuration for each of its interfaces
// Carries the networking configs specified in the `docker run` and `docker network connect` commands
type NetworkingConfig struct {
	EndpointsConfig map[string]*EndpointConfig // Endpoint configs for each connecting network
}

// StartContainer starts a container, returning an error in case of failure.
//
// Passing the HostConfig to this method has been deprecated in Docker API 1.22
// (Docker Engine 1.10.x) and totally removed in Docker API 1.24 (Docker Engine
// 1.12.x). The client will ignore the parameter when communicating with Docker
// API 1.24 or greater.
//
// See https://goo.gl/MrBAJv for more details.
func (c *Client) StartContainer(id string, hostConfig *HostConfig) error {
	var opts doOptions
	path := "/containers/" + id + "/start"
	if c.serverAPIVersion == nil {
		c.checkAPIVersion()
	}
	if c.serverAPIVersion != nil && c.serverAPIVersion.LessThan(apiVersion124) {
		opts = doOptions{data: hostConfig, forceJSON: true}
	}
	resp, err := c.do("POST", path, opts)
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: id, Err: err}
		}
		return err
	}
	if resp.StatusCode == http.StatusNotModified {
		return &ContainerAlreadyRunning{ID: id}
	}
	resp.Body.Close()
	return nil
}

// StopContainer stops a container, killing it after the given timeout (in
// seconds).
//
// See https://goo.gl/USqsFt for more details.
func (c *Client) StopContainer(id string, timeout uint) error {
	path := fmt.Sprintf("/containers/%s/stop?t=%d", id, timeout)
	resp, err := c.do("POST", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: id}
		}
		return err
	}
	if resp.StatusCode == http.StatusNotModified {
		return &ContainerNotRunning{ID: id}
	}
	resp.Body.Close()
	return nil
}

// RestartContainer stops a container, killing it after the given timeout (in
// seconds), during the stop process.
//
// See https://goo.gl/QzsDnz for more details.
func (c *Client) RestartContainer(id string, timeout uint) error {
	path := fmt.Sprintf("/containers/%s/restart?t=%d", id, timeout)
	resp, err := c.do("POST", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: id}
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// PauseContainer pauses the given container.
//
// See https://goo.gl/OF7W9X for more details.
func (c *Client) PauseContainer(id string) error {
	path := fmt.Sprintf("/containers/%s/pause", id)
	resp, err := c.do("POST", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: id}
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// UnpauseContainer unpauses the given container.
//
// See https://goo.gl/7dwyPA for more details.
func (c *Client) UnpauseContainer(id string) error {
	path := fmt.Sprintf("/containers/%s/unpause", id)
	resp, err := c.do("POST", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: id}
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// TopResult represents the list of processes running in a container, as
// returned by /containers/<id>/top.
//
// See https://goo.gl/Rb46aY for more details.
type TopResult struct {
	Titles    []string
	Processes [][]string
}

// TopContainer returns processes running inside a container
//
// See https://goo.gl/Rb46aY for more details.
func (c *Client) TopContainer(id string, psArgs string) (TopResult, error) {
	var args string
	var result TopResult
	if psArgs != "" {
		args = fmt.Sprintf("?ps_args=%s", psArgs)
	}
	path := fmt.Sprintf("/containers/%s/top%s", id, args)
	resp, err := c.do("GET", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return result, &NoSuchContainer{ID: id}
		}
		return result, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, err
	}
	return result, nil
}

// Stats represents container statistics, returned by /containers/<id>/stats.
//
// See https://goo.gl/GNmLHb for more details.
type Stats struct {
	Read      time.Time `json:"read" yaml:"read"`
	PidsStats struct {
		Current uint64 `json:"current" yaml:"current"`
	} `json:"pids_stats" yaml:"pids_stats"`
	Network     NetworkStats            `json:"network" yaml:"network"`
	Networks    map[string]NetworkStats `json:"networks" yaml:"networks"`
	MemoryStats struct {
		Stats struct {
			TotalPgmafault          uint64 `json:"total_pgmafault" yaml:"total_pgmafault"`
			Cache                   uint64 `json:"cache" yaml:"cache"`
			MappedFile              uint64 `json:"mapped_file" yaml:"mapped_file"`
			TotalInactiveFile       uint64 `json:"total_inactive_file" yaml:"total_inactive_file"`
			Pgpgout                 uint64 `json:"pgpgout" yaml:"pgpgout"`
			Rss                     uint64 `json:"rss" yaml:"rss"`
			TotalMappedFile         uint64 `json:"total_mapped_file" yaml:"total_mapped_file"`
			Writeback               uint64 `json:"writeback" yaml:"writeback"`
			Unevictable             uint64 `json:"unevictable" yaml:"unevictable"`
			Pgpgin                  uint64 `json:"pgpgin" yaml:"pgpgin"`
			TotalUnevictable        uint64 `json:"total_unevictable" yaml:"total_unevictable"`
			Pgmajfault              uint64 `json:"pgmajfault" yaml:"pgmajfault"`
			TotalRss                uint64 `json:"total_rss" yaml:"total_rss"`
			TotalRssHuge            uint64 `json:"total_rss_huge" yaml:"total_rss_huge"`
			TotalWriteback          uint64 `json:"total_writeback" yaml:"total_writeback"`
			TotalInactiveAnon       uint64 `json:"total_inactive_anon" yaml:"total_inactive_anon"`
			RssHuge                 uint64 `json:"rss_huge" yaml:"rss_huge"`
			HierarchicalMemoryLimit uint64 `json:"hierarchical_memory_limit" yaml:"hierarchical_memory_limit"`
			TotalPgfault            uint64 `json:"total_pgfault" yaml:"total_pgfault"`
			TotalActiveFile         uint64 `json:"total_active_file" yaml:"total_active_file"`
			ActiveAnon              uint64 `json:"active_anon" yaml:"active_anon"`
			TotalActiveAnon         uint64 `json:"total_active_anon" yaml:"total_active_anon"`
			TotalPgpgout            uint64 `json:"total_pgpgout" yaml:"total_pgpgout"`
			TotalCache              uint64 `json:"total_cache" yaml:"total_cache"`
			InactiveAnon            uint64 `json:"inactive_anon" yaml:"inactive_anon"`
			ActiveFile              uint64 `json:"active_file" yaml:"active_file"`
			Pgfault                 uint64 `json:"pgfault" yaml:"pgfault"`
			InactiveFile            uint64 `json:"inactive_file" yaml:"inactive_file"`
			TotalPgpgin             uint64 `json:"total_pgpgin" yaml:"total_pgpgin"`
			HierarchicalMemswLimit  uint64 `json:"hierarchical_memsw_limit" yaml:"hierarchical_memsw_limit"`
			Swap                    uint64 `json:"swap" yaml:"swap"`
		} `json:"stats" yaml:"stats"`
		MaxUsage uint64 `json:"max_usage" yaml:"max_usage"`
		Usage    uint64 `json:"usage" yaml:"usage"`
		Failcnt  uint64 `json:"failcnt" yaml:"failcnt"`
		Limit    uint64 `json:"limit" yaml:"limit"`
	} `json:"memory_stats" yaml:"memory_stats"`
	BlkioStats struct {
		IOServiceBytesRecursive []BlkioStatsEntry `json:"io_service_bytes_recursive" yaml:"io_service_bytes_recursive"`
		IOServicedRecursive     []BlkioStatsEntry `json:"io_serviced_recursive" yaml:"io_serviced_recursive"`
		IOQueueRecursive        []BlkioStatsEntry `json:"io_queue_recursive" yaml:"io_queue_recursive"`
		IOServiceTimeRecursive  []BlkioStatsEntry `json:"io_service_time_recursive" yaml:"io_service_time_recursive"`
		IOWaitTimeRecursive     []BlkioStatsEntry `json:"io_wait_time_recursive" yaml:"io_wait_time_recursive"`
		IOMergedRecursive       []BlkioStatsEntry `json:"io_merged_recursive" yaml:"io_merged_recursive"`
		IOTimeRecursive         []BlkioStatsEntry `json:"io_time_recursive" yaml:"io_time_recursive"`
		SectorsRecursive        []BlkioStatsEntry `json:"sectors_recursive" yaml:"sectors_recursive"`
	} `json:"blkio_stats" yaml:"blkio_stats"`
	CPUStats    CPUStats `json:"cpu_stats" yaml:"cpu_stats"`
	PreCPUStats CPUStats `json:"precpu_stats"`
}

// NetworkStats is a stats entry for network stats
type NetworkStats struct {
	RxDropped uint64 `json:"rx_dropped" yaml:"rx_dropped"`
	RxBytes   uint64 `json:"rx_bytes" yaml:"rx_bytes"`
	RxErrors  uint64 `json:"rx_errors" yaml:"rx_errors"`
	TxPackets uint64 `json:"tx_packets" yaml:"tx_packets"`
	TxDropped uint64 `json:"tx_dropped" yaml:"tx_dropped"`
	RxPackets uint64 `json:"rx_packets" yaml:"rx_packets"`
	TxErrors  uint64 `json:"tx_errors" yaml:"tx_errors"`
	TxBytes   uint64 `json:"tx_bytes" yaml:"tx_bytes"`
}

// CPUStats is a stats entry for cpu stats
type CPUStats struct {
	CPUUsage struct {
		PercpuUsage       []uint64 `json:"percpu_usage" yaml:"percpu_usage"`
		UsageInUsermode   uint64   `json:"usage_in_usermode" yaml:"usage_in_usermode"`
		TotalUsage        uint64   `json:"total_usage" yaml:"total_usage"`
		UsageInKernelmode uint64   `json:"usage_in_kernelmode" yaml:"usage_in_kernelmode"`
	} `json:"cpu_usage" yaml:"cpu_usage"`
	SystemCPUUsage uint64 `json:"system_cpu_usage" yaml:"system_cpu_usage"`
	ThrottlingData struct {
		Periods          uint64 `json:"periods"`
		ThrottledPeriods uint64 `json:"throttled_periods"`
		ThrottledTime    uint64 `json:"throttled_time"`
	} `json:"throttling_data" yaml:"throttling_data"`
}

// BlkioStatsEntry is a stats entry for blkio_stats
type BlkioStatsEntry struct {
	Major uint64 `json:"major" yaml:"major"`
	Minor uint64 `json:"minor" yaml:"minor"`
	Op    string `json:"op" yaml:"op"`
	Value uint64 `json:"value" yaml:"value"`
}

// StatsOptions specify parameters to the Stats function.
//
// See https://goo.gl/GNmLHb for more details.
type StatsOptions struct {
	ID     string
	Stats  chan<- *Stats
	Stream bool
	// A flag that enables stopping the stats operation
	Done <-chan bool
	// Initial connection timeout
	Timeout time.Duration
	// Timeout with no data is received, it's reset every time new data
	// arrives
	InactivityTimeout time.Duration `qs:"-"`
}

// Stats sends container statistics for the given container to the given channel.
//
// This function is blocking, similar to a streaming call for logs, and should be run
// on a separate goroutine from the caller. Note that this function will block until
// the given container is removed, not just exited. When finished, this function
// will close the given channel. Alternatively, function can be stopped by
// signaling on the Done channel.
//
// See https://goo.gl/GNmLHb for more details.
func (c *Client) Stats(opts StatsOptions) (retErr error) {
	errC := make(chan error, 1)
	readCloser, writeCloser := io.Pipe()

	defer func() {
		close(opts.Stats)

		select {
		case err := <-errC:
			if err != nil && retErr == nil {
				retErr = err
			}
		default:
			// No errors
		}

		if err := readCloser.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	go func() {
		err := c.stream("GET", fmt.Sprintf("/containers/%s/stats?stream=%v", opts.ID, opts.Stream), streamOptions{
			rawJSONStream:     true,
			useJSONDecoder:    true,
			stdout:            writeCloser,
			timeout:           opts.Timeout,
			inactivityTimeout: opts.InactivityTimeout,
		})
		if err != nil {
			dockerError, ok := err.(*Error)
			if ok {
				if dockerError.Status == http.StatusNotFound {
					err = &NoSuchContainer{ID: opts.ID}
				}
			}
		}
		if closeErr := writeCloser.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		errC <- err
		close(errC)
	}()

	quit := make(chan struct{})
	defer close(quit)
	go func() {
		// block here waiting for the signal to stop function
		select {
		case <-opts.Done:
			readCloser.Close()
		case <-quit:
			return
		}
	}()

	decoder := json.NewDecoder(readCloser)
	stats := new(Stats)
	for err := decoder.Decode(stats); err != io.EOF; err = decoder.Decode(stats) {
		if err != nil {
			return err
		}
		opts.Stats <- stats
		stats = new(Stats)
	}
	return nil
}

// KillContainerOptions represents the set of options that can be used in a
// call to KillContainer.
//
// See https://goo.gl/hkS9i8 for more details.
type KillContainerOptions struct {
	// The ID of the container.
	ID string `qs:"-"`

	// The signal to send to the container. When omitted, Docker server
	// will assume SIGKILL.
	Signal Signal
}

// KillContainer sends a signal to a container, returning an error in case of
// failure.
//
// See https://goo.gl/hkS9i8 for more details.
func (c *Client) KillContainer(opts KillContainerOptions) error {
	path := "/containers/" + opts.ID + "/kill" + "?" + queryString(opts)
	resp, err := c.do("POST", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: opts.ID}
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// RemoveContainerOptions encapsulates options to remove a container.
//
// See https://goo.gl/RQyX62 for more details.
type RemoveContainerOptions struct {
	// The ID of the container.
	ID string `qs:"-"`

	// A flag that indicates whether Docker should remove the volumes
	// associated to the container.
	RemoveVolumes bool `qs:"v"`

	// A flag that indicates whether Docker should remove the container
	// even if it is currently running.
	Force bool
}

// RemoveContainer removes a container, returning an error in case of failure.
//
// See https://goo.gl/RQyX62 for more details.
func (c *Client) RemoveContainer(opts RemoveContainerOptions) error {
	path := "/containers/" + opts.ID + "?" + queryString(opts)
	resp, err := c.do("DELETE", path, doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: opts.ID}
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// UploadToContainerOptions is the set of options that can be used when
// uploading an archive into a container.
//
// See https://goo.gl/Ss97HW for more details.
type UploadToContainerOptions struct {
	InputStream          io.Reader `json:"-" qs:"-"`
	Path                 string    `qs:"path"`
	NoOverwriteDirNonDir bool      `qs:"noOverwriteDirNonDir"`
}

// UploadToContainer uploads a tar archive to be extracted to a path in the
// filesystem of the container.
//
// See https://goo.gl/Ss97HW for more details.
func (c *Client) UploadToContainer(id string, opts UploadToContainerOptions) error {
	url := fmt.Sprintf("/containers/%s/archive?", id) + queryString(opts)

	return c.stream("PUT", url, streamOptions{
		in: opts.InputStream,
	})
}

// DownloadFromContainerOptions is the set of options that can be used when
// downloading resources from a container.
//
// See https://goo.gl/KnZJDX for more details.
type DownloadFromContainerOptions struct {
	OutputStream      io.Writer     `json:"-" qs:"-"`
	Path              string        `qs:"path"`
	InactivityTimeout time.Duration `qs:"-"`
}

// DownloadFromContainer downloads a tar archive of files or folders in a container.
//
// See https://goo.gl/KnZJDX for more details.
func (c *Client) DownloadFromContainer(id string, opts DownloadFromContainerOptions) error {
	url := fmt.Sprintf("/containers/%s/archive?", id) + queryString(opts)

	return c.stream("GET", url, streamOptions{
		setRawTerminal:    true,
		stdout:            opts.OutputStream,
		inactivityTimeout: opts.InactivityTimeout,
	})
}

// CopyFromContainerOptions has been DEPRECATED, please use DownloadFromContainerOptions along with DownloadFromContainer.
//
// See https://goo.gl/R2jevW for more details.
type CopyFromContainerOptions struct {
	OutputStream io.Writer `json:"-"`
	Container    string    `json:"-"`
	Resource     string
}

// CopyFromContainer has been DEPRECATED, please use DownloadFromContainerOptions along with DownloadFromContainer.
//
// See https://goo.gl/R2jevW for more details.
func (c *Client) CopyFromContainer(opts CopyFromContainerOptions) error {
	if opts.Container == "" {
		return &NoSuchContainer{ID: opts.Container}
	}
	url := fmt.Sprintf("/containers/%s/copy", opts.Container)
	resp, err := c.do("POST", url, doOptions{data: opts})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return &NoSuchContainer{ID: opts.Container}
		}
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(opts.OutputStream, resp.Body)
	return err
}

// WaitContainer blocks until the given container stops, return the exit code
// of the container status.
//
// See https://goo.gl/Gc1rge for more details.
func (c *Client) WaitContainer(id string) (int, error) {
	resp, err := c.do("POST", "/containers/"+id+"/wait", doOptions{})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return 0, &NoSuchContainer{ID: id}
		}
		return 0, err
	}
	defer resp.Body.Close()
	var r struct{ StatusCode int }
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, err
	}
	return r.StatusCode, nil
}

// CommitContainerOptions aggregates parameters to the CommitContainer method.
//
// See https://goo.gl/mqfoCw for more details.
type CommitContainerOptions struct {
	Container  string
	Repository string `qs:"repo"`
	Tag        string
	Message    string `qs:"comment"`
	Author     string
	Run        *Config `qs:"-"`
}

// CommitContainer creates a new image from a container's changes.
//
// See https://goo.gl/mqfoCw for more details.
func (c *Client) CommitContainer(opts CommitContainerOptions) (*Image, error) {
	path := "/commit?" + queryString(opts)
	resp, err := c.do("POST", path, doOptions{data: opts.Run})
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return nil, &NoSuchContainer{ID: opts.Container}
		}
		return nil, err
	}
	defer resp.Body.Close()
	var image Image
	if err := json.NewDecoder(resp.Body).Decode(&image); err != nil {
		return nil, err
	}
	return &image, nil
}

// AttachToContainerOptions is the set of options that can be used when
// attaching to a container.
//
// See https://goo.gl/NKpkFk for more details.
type AttachToContainerOptions struct {
	Container    string    `qs:"-"`
	InputStream  io.Reader `qs:"-"`
	OutputStream io.Writer `qs:"-"`
	ErrorStream  io.Writer `qs:"-"`

	// Get container logs, sending it to OutputStream.
	Logs bool

	// Stream the response?
	Stream bool

	// Attach to stdin, and use InputStream.
	Stdin bool

	// Attach to stdout, and use OutputStream.
	Stdout bool

	// Attach to stderr, and use ErrorStream.
	Stderr bool

	// If set, after a successful connect, a sentinel will be sent and then the
	// client will block on receive before continuing.
	//
	// It must be an unbuffered channel. Using a buffered channel can lead
	// to unexpected behavior.
	Success chan struct{}

	// Use raw terminal? Usually true when the container contains a TTY.
	RawTerminal bool `qs:"-"`
}

// AttachToContainer attaches to a container, using the given options.
//
// See https://goo.gl/NKpkFk for more details.
func (c *Client) AttachToContainer(opts AttachToContainerOptions) error {
	cw, err := c.AttachToContainerNonBlocking(opts)
	if err != nil {
		return err
	}
	return cw.Wait()
}

// AttachToContainerNonBlocking attaches to a container, using the given options.
// This function does not block.
//
// See https://goo.gl/NKpkFk for more details.
func (c *Client) AttachToContainerNonBlocking(opts AttachToContainerOptions) (CloseWaiter, error) {
	if opts.Container == "" {
		return nil, &NoSuchContainer{ID: opts.Container}
	}
	path := "/containers/" + opts.Container + "/attach?" + queryString(opts)
	return c.hijack("POST", path, hijackOptions{
		success:        opts.Success,
		setRawTerminal: opts.RawTerminal,
		in:             opts.InputStream,
		stdout:         opts.OutputStream,
		stderr:         opts.ErrorStream,
	})
}

// LogsOptions represents the set of options used when getting logs from a
// container.
//
// See https://goo.gl/yl8PGm for more details.
type LogsOptions struct {
	Container         string        `qs:"-"`
	OutputStream      io.Writer     `qs:"-"`
	ErrorStream       io.Writer     `qs:"-"`
	InactivityTimeout time.Duration `qs:"-"`
	Follow            bool
	Stdout            bool
	Stderr            bool
	Since             int64
	Timestamps        bool
	Tail              string

	// Use raw terminal? Usually true when the container contains a TTY.
	RawTerminal bool `qs:"-"`
}

// Logs gets stdout and stderr logs from the specified container.
//
// See https://goo.gl/yl8PGm for more details.
func (c *Client) Logs(opts LogsOptions) error {
	if opts.Container == "" {
		return &NoSuchContainer{ID: opts.Container}
	}
	if opts.Tail == "" {
		opts.Tail = "all"
	}
	path := "/containers/" + opts.Container + "/logs?" + queryString(opts)
	return c.stream("GET", path, streamOptions{
		setRawTerminal:    opts.RawTerminal,
		stdout:            opts.OutputStream,
		stderr:            opts.ErrorStream,
		inactivityTimeout: opts.InactivityTimeout,
	})
}

// ResizeContainerTTY resizes the terminal to the given height and width.
//
// See https://goo.gl/xERhCc for more details.
func (c *Client) ResizeContainerTTY(id string, height, width int) error {
	params := make(url.Values)
	params.Set("h", strconv.Itoa(height))
	params.Set("w", strconv.Itoa(width))
	resp, err := c.do("POST", "/containers/"+id+"/resize?"+params.Encode(), doOptions{})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ExportContainerOptions is the set of parameters to the ExportContainer
// method.
//
// See https://goo.gl/dOkTyk for more details.
type ExportContainerOptions struct {
	ID                string
	OutputStream      io.Writer
	InactivityTimeout time.Duration `qs:"-"`
}

// ExportContainer export the contents of container id as tar archive
// and prints the exported contents to stdout.
//
// See https://goo.gl/dOkTyk for more details.
func (c *Client) ExportContainer(opts ExportContainerOptions) error {
	if opts.ID == "" {
		return &NoSuchContainer{ID: opts.ID}
	}
	url := fmt.Sprintf("/containers/%s/export", opts.ID)
	return c.stream("GET", url, streamOptions{
		setRawTerminal:    true,
		stdout:            opts.OutputStream,
		inactivityTimeout: opts.InactivityTimeout,
	})
}

// NoSuchContainer is the error returned when a given container does not exist.
type NoSuchContainer struct {
	ID  string
	Err error
}

func (err *NoSuchContainer) Error() string {
	if err.Err != nil {
		return err.Err.Error()
	}
	return "No such container: " + err.ID
}

// ContainerAlreadyRunning is the error returned when a given container is
// already running.
type ContainerAlreadyRunning struct {
	ID string
}

func (err *ContainerAlreadyRunning) Error() string {
	return "Container already running: " + err.ID
}

// ContainerNotRunning is the error returned when a given container is not
// running.
type ContainerNotRunning struct {
	ID string
}

func (err *ContainerNotRunning) Error() string {
	return "Container not running: " + err.ID
}

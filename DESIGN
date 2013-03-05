# Quark

## Why

We don't have centralized networking services. Quantum is incapable of talking to melange, melange <em>could</em> talk to Quantum,
but then we're bothering with HTTPS handshaking for no reason. Alternatively, we need to retain the network manager as a traffic
arbiter. Given the upstream push to eliminate the network managers and move entirely to quantum, we needed to consider alternative
solutions. Given that we'd like to avoid making melange a glorified network manager, we originally decided we want to write a
Quantum-lite, named Newtonian, as our first pass. However, resistance from the company pushed us to try and write a solution that
fits within the goals of the community itself. Hence, Quark was born.

## History

Nova provided a network manager type of Flat, which allows us to easily give out real-world public IPv4 and v6 addresses without any oversight
from Nova itself. Meanwhile, Quantum appears, and implements L2 logical networking. However, it leaves Nova as the IPAM solution for the cloud.
Rackspace begins development of a solution called Melange, intended to abstract IPAM and provide it at a different tier in the Openstack stack.
Melange is a functional, performant solution for providing IP addressing and MAC addressing to instances created by Nova. However, Quantum, running
certain backends, has serious performance and stability problems. Work began on Melange to fold in some manner of caching of Quantum resources
and added stability. However, the community begins the push for a rewrite of Quantum, which promises to provide a DB abstraction as well as IPAM.
The caveat is the implementation of each is left up to the developer of each plugin, meaning no IPAM solution is likely to be compatible with one another.
This creates a problem for Rackspace, who 1) doesn't want to be tied to a given Quantum backend and 2) doesn't want to be stuck with a potentially gimped
IPAM solution. As such, work on Newtonian begins. After much debate with the community and internal Rackspace folks, it's finally decided that Newtonian
represents a fork, which is a Bad Thing™. Given that, we decide that the next bset solution is to provide a Quantum plugin that implements the Rackspace
preferred backend with the intent of providing Quantum wide IPAM, Mac Addressing, and networking abstractions, with less dependence on a given backend.

## Nice to Haves

* As a product manager, I want less dependency on Quantum.
*   I want my builds to have more parallel functioning pieces, which means I want my networking request to be fulfilled at the same time as other operations
* As Rackspace, I may need MDI to keep selling

## Priorities first to last

1. Robustness
1. Scaling / Performance
1. Development time
1. Vendor lockin

## Problems As Justin wrote them

* Switching to QV2 will DoS Backend with current oimplementation, just with GETs
* Current is non-performant
* Network Manager needs to go away
* Too many REST calls in current quantum client
* Current IMPL does not support bulk operations on nested resources
* Quantum <-> Backend delay causing building
* Unknown performance hit with increased requests to backend
* Backend requests are non-deterministic
* Vendor-locking is a bad thing
* Unified networking information model

## Non-functional requirements

* Benchmarking for justification
* Performance
* Scalinghh
* Robustness
* Vendor-lockin

## Descriptions and Solutions of Problems

### Switching to QV2 will DoS Backend with current implementation

DoS'd due to GETs when Nova is trying to retrieve instance network info in the periodic tasks. We currently get around it by providing this data
in melange. We're doing the same thing in the Quark Model by storing all relevant bits in the database. This database creates a single authoritative
source of all network state

DoSing due to POSTs when creating networks. One possible solution is to implement a manner of asynchronously creating networking information via Request
IDs or other similar constructs.

### Current Quantum solution is non-performant

Current REST implementation forces you to make piecemeal requests. You need to look up networks to find your subnets. Then look up each port by subnet. Beyond that,
individual operations can explode into an unknown number of backend operations. We feel that the safer solution is to assume that the backend will behave badly,
and limit the number of calls we need to make to it.

### Network Manager needs to go away

This is a unilateral community decision. We need to shift out dependence on the quantumv2 manager up to the quantum network API and down into Quark/Quantum

### Too many REST calls in current quantum client

This is by design. Reworking the above non-performant problem also necessitates reworking the CLI to make less calls

### Current IMPL does not support bulk operations on nested resources

Original V2 API for quantum provided this construct, which was then removed. We can solve this by removing the check to perform the bulk

### Quantum <-> Backend delay causing building

By eliminating some of the superfluous calls to the backend, we hope to reduce the length of the timeouts required to remain robust

### Unknown performance hit with increased requests to the Network Backend

Since we don't know what the backend is going to do with a given operation, as above, eliminating the calls as above helps us zero in on the problem

### Backend request times are non-determinstic

We can't solve this, we can only rely on it less

### Vendor lock-in is bad

Denormalizing Quantum constructs into a database helps use mitigate for this problem

### A unified network model

We feel that we may spend too much time converting from one structure of the networking information to another. The schema for Quark more closely models what Nova is expecting

## User Stories and Epics

#### As a product manager, I need IPAM in a service deployable at a region level

We need to provide APIs for adding and removing IP addresses to arbitrary devices. Instances are folded under this.

#### As a product manager, I need Mac Address management in a central service that can be deployed at the region level

We need to provide APIs for adding and removing MAC addresses to arbitrary devices. Instances are folded under this.

#### As an openstack community member, I need to provide a networking solution that can be used by the community

Implement Quark as Yet Another Quantum plugin (YAQ)™ with bundled extensions. The intent is to trickle ideas up

#### As an ops engineer, I need Nova to make less calls to Quantum to prevent kicking it over.

Implementation of a database layer that let's us eliminate alot of the calls the existing plugins are making to the networking backend

####   I need to be able to create a network with all of it's subnets in a single call
#### As an ops engineer, I need Quantum to make less call to the Networking Backend to mitigate timeouts and throttling
#### As a Rackspace developer, I want less code to maintain that is a diff from upstream Openstack.
#### As a Rackspace developer, I want an extension in Quantum that allows me to bulk create all networking for an instance in a single call.
#### As a Rackspace developer, I want a Quantum abstraction that depends less heavily on the networking backend
#### As a product manager, I need MAC Address ranges to be available to all tenants of Quantum/Quark
#### As a Quantum user, I need a consistent API
#### As a Quantum user, I need a consistently performing API
#### As Rackspace, I need less build failures due to networking setup timeouts talking to the Quantum backend
#### As Rackspace, I want faster instance build times, which are dependent on a responsive Quantum
####   As a customer, I want faster build times
#### As Rackspace, I don't want to be locked into any Vendor
#### As the network team manager, I need benchmarks to show the improvement of Quark over vanilla Quantum
#### As the network team manager, I need measurable improvements in Quark on a regular basis
#### As a Rackspace developer, I need a design document with the extended API for Quark to present to the community
#### As a user, I need a way to create routes for my networks
#### As a user, I need a way to request additional IP addresses from my networks.
#### As a user, I need a way to share IP addresses across my ports

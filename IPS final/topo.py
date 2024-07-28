#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():
    net = Mininet( topo=None,
                   build=False,
                   ipBase='192.168.100.0/24')

    info( '*** Adding controller\n' )

    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='192.168.133.128',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    #Intf( 'ens33', node=s4 )

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', mac="00:00:00:00:00:01",defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', mac="00:00:00:00:00:02",defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', mac="00:00:00:00:00:03",defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', mac="00:00:00:00:00:04",defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', mac="00:00:00:00:00:05",defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', mac="00:00:00:00:00:06",defaultRoute=None)
    h7 = net.addHost('h7', cls=Host, ip='10.0.0.7', mac="00:00:00:00:00:07",defaultRoute=None)
    h8 = net.addHost('h8', cls=Host, ip='10.0.0.8', mac="00:00:00:00:00:08",defaultRoute=None)
    h9 = net.addHost('h9', cls=Host, ip='10.0.0.9', mac="00:00:00:00:00:09",defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(h8, s4)
    net.addLink(h9, s4)
    net.addLink(s2, s1)
    net.addLink(s2, s3)
    net.addLink(s1, s4)
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s2, h3)
    net.addLink(s2, h4)
    net.addLink(s2, h5)
    net.addLink(s3, h6)
    net.addLink(s3, h7)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    
    #h1 = net.get('h1')
    #h1.cmd('xterm &')
    
    #info( '*** Connecting h8 to internet\n')
    #h8.cmdPrint('dhclient '+h8.defaultIntf().name)
    #info( '*** Starting web server in h2\n')
    #h2.cmd('python web.py')
    #info( '*** Starting ftp server in h4\n')
    #sh4.cmd('python ftp.py')
    #info( '*** Starting iperf server in h6\n')
    #h6.cmd('iperf -s -p 5005 -i 1')

    info( '*** Configuration is done, Network started.\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()



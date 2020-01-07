/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
///

#define NS_LOG_APPEND_CONTEXT                                   \
  if (GetObject<Node> ()) { std::clog << "[node " << GetObject<Node> ()->GetId () << "] "; }
  
//用olsr的数据，还是olsr上用molsr的数据
#include "molsr-routing-protocol.h"
#include "ns3/socket-factory.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/names.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-static-routing.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-routing-table-entry.h"
#include "ns3/ipv4-route.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/enum.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-packet-info-tag.h"


namespace ns3
{

NS_LOG_COMPONENT_DEFINE("MolsrRoutingProtocol");

namespace molsr
{

/********** MOLSR class **********/

NS_OBJECT_ENSURE_REGISTERED(MulticastRoutingProtocol);
//唯一标示
TypeId
MulticastRoutingProtocol::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::molsr::MulticastRoutingProtocol")
                          .SetParent<Ipv4RoutingProtocol>()
                          .SetGroupName("Molsr")
                          .AddConstructor<MulticastRoutingProtocol>()
                          .AddTraceSource("Rx", "Receive MOLSR packet.",
                                          MakeTraceSourceAccessor(&MulticastRoutingProtocol::m_rxPacketTrace),
                                          "ns3::molsr::MulticastRoutingProtocol::PacketTxRxTracedCallback")
                          .AddTraceSource("Tx", "Send MOLSR packet.",
                                          MakeTraceSourceAccessor(&MulticastRoutingProtocol::m_txPacketTrace),
                                          "ns3::molsr::MulticastRoutingProtocol::PacketTxRxTracedCallback")
                          .AddTraceSource("MulticastRoutingTableChanged", "The MOLSR routing table has changed.", //xtt.molsr
                                          MakeTraceSourceAccessor(&MulticastRoutingProtocol::m_multicastRoutingTableChanged),
                                          "ns3::molsr::MulticastRoutingProtocol::TableChangeTracedCallback")
                          .AddTraceSource("MulticastTreeChanged", "The MOLSR routing table has changed.", //xtt.molsr
                                          MakeTraceSourceAccessor(&MulticastRoutingProtocol::m_multicastTreeChanged),
                                          "ns3::molsr::MulticastRoutingProtocol::TreeChangeTracedCallback") /////////多播树改变
                                         ;
      
  return tid;
}

MulticastRoutingProtocol::MulticastRoutingProtocol()
    : //xtt-molsr
      m_mipv4(0),
      m_mclaimTimer(Timer::CANCEL_ON_DESTROY), //xtt----molsr
      m_sourceclaimTimer(Timer::CANCEL_ON_DESTROY),
      m_confirmparentTimer(Timer::CANCEL_ON_DESTROY),
      m_leaveTimer(Timer::CANCEL_ON_DESTROY),
      m_queuedMessagesTimer(Timer::CANCEL_ON_DESTROY)
{
  m_uniformRandomVariable = CreateObject<UniformRandomVariable>();
  //m_hnaMulticastRoutingTable = Create<Ipv4StaticRouting> ();//xtt   molsr
  // dropCount = 0;
}

MulticastRoutingProtocol::~MulticastRoutingProtocol()
{
}

void MulticastRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
  NS_ASSERT(ipv4 != 0);
  NS_ASSERT(m_mipv4 == 0);
  NS_LOG_DEBUG("Created molsr::MulticastRoutingProtocol");
  //xtt  molsr  设置定时器
  Ptr<Ipv4RoutingProtocol> (olsr)->SetIpv4(ipv4);
  m_mclaimTimer.SetFunction(&MulticastRoutingProtocol::MclaimTimerExpire, this);
  m_sourceclaimTimer.SetFunction(&MulticastRoutingProtocol::SourceTimerExpire, this);
  m_confirmparentTimer.SetFunction(&MulticastRoutingProtocol::ConfirmTimerExpire, this);
  m_leaveTimer.SetFunction(&MulticastRoutingProtocol::LeaveTimerExpire, this);

  m_queuedMessagesTimer.SetFunction(&MulticastRoutingProtocol::SendQueuedMessages, this);

  m_packetSequenceNumber = MOLSR_MAX_SEQ_NUM;
  m_messageSequenceNumber = MOLSR_MAX_SEQ_NUM;
  m_ansn = MOLSR_MAX_SEQ_NUM;
  m_mipv4 = ipv4;

  //设置hna多播路由表xtt   molsr
  // m_hnaMulticastRoutingTable->SetIpv4 (ipv4);
}

void MulticastRoutingProtocol::DoDispose()
{
  m_mipv4 = 0;

  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    iter->first->Close(); ////关闭所有接口？
  }
  m_socketAddresses.clear(); //清除接口信息？？？？

  Ipv4RoutingProtocol::DoDispose();
}

////xtttmolsr     打印多播路由表
void MulticastRoutingProtocol::PrintMolsrRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit ) const
{
  std::ostream *os = stream->GetStream();

  *os << "Node: " << m_mipv4->GetObject<Node>()->GetId()
      << ", Time: " << Now().As (unit)
      << ", Local time: " << GetObject<Node>()->GetLocalTime().As (unit)
      << ", MOLSR Routing table" << std::endl;

  *os << "Destination\t\tNextHop\tDistance\n";

  for (std::map<Ipv4Address, MulticastRoutingTableEntry>::const_iterator iter = m_mtable.begin();
       iter != m_mtable.end(); iter++)
  {
    *os << iter->first << "\t\t";             //目的地址
    *os << iter->second.MRnextAddr << "\t\t"; //不考虑接口问题
    if (Names::FindName(m_mipv4->GetNetDevice(iter->second.MRinterface)) != "")
    {
      *os << Names::FindName(m_mipv4->GetNetDevice(iter->second.MRinterface)) << "\t\t";
    }
    else
    {
      *os << iter->second.MRinterface << "\t\t";
    }
    *os << iter->second.MRdistance << "\t";
    *os << "\n";
  }
}

/////////疑问！！！！！！！1
void MulticastRoutingProtocol::DoInitialize()
{
  //olsr->DoInitialize();
  if (m_mainAddress == Ipv4Address())
  {
    Ipv4Address loopback("127.0.0.1");
    for (uint32_t i = 0; i < m_mipv4->GetNInterfaces(); i++)
    {
      // 如果GetAddress (i, 0)每个接口有多个地址，取第一个GetLocal ()接口地址
      Ipv4Address addr = m_mipv4->GetAddress(i, 0).GetLocal();
      if (addr != loopback)
      {
        m_mainAddress = addr;
        break;
      }
    }
    //如果主地址不是ipv4地址就停止
    NS_ASSERT(m_mainAddress != Ipv4Address());
  }

  NS_LOG_DEBUG("Starting MOLSR on node " << m_mainAddress);

  Ipv4Address loopback("127.0.0.1");
  //判断可否运行molsr，，，，假设都可以呢???????  遍历所有接口找寻可以运行molsr的接口
  bool canRunMolsr = false;
  for (uint32_t i = 0; i < m_mipv4->GetNInterfaces(); i++)
  {
    Ipv4Address addr = m_mipv4->GetAddress(i, 0).GetLocal();
    //回环地址，则往下一个寻找
    if (addr == loopback)
    {
      continue;
    }
    //如果没有等于主地址的接口，则新建一个接口关联表，添加主地址项。
    if (addr != m_mainAddress)
    {
      // Create never expiring interface association tuple entries for our
      // own network interfaces, so that olsr->GetMainAddress () 将接口地址转化为主地址，，，，，，创建tuple，，接口地址设位每个不是主地址的地址
      IfaceAssocTuple tuple;
      tuple.ifaceAddr = addr;
      tuple.mainAddr = m_mainAddress;
      olsr->AddIfaceAssocTuple(tuple);
      NS_ASSERT(olsr->GetMainAddress(addr) == m_mainAddress);
    }
    /////////////////排除第i个接口
    if (m_interfaceExclusions.find(i) != m_interfaceExclusions.end())
    {
      continue;
    }

    // Create a socket to listen only on this interface
    Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(),
                                              UdpSocketFactory::GetTypeId());
    socket->SetAllowBroadcast(true);
    InetSocketAddress inetAddr(m_mipv4->GetAddress(i, 0).GetLocal(), MOLSR_PORT_NUMBER); //第一个接口地址
    socket->SetRecvCallback(MakeCallback(&MulticastRoutingProtocol::RecvMolsr, this));//socket success , run the recvmolsr
    NS_LOG_DEBUG("create socket" );

    /////////绑定成功socket地址
    if (socket->Bind(inetAddr))
    {
      NS_FATAL_ERROR("Failed to bind() MOLSR socket");
    }
    //绑定设备
    socket->BindToNetDevice(m_mipv4->GetNetDevice(i));
    m_socketAddresses[socket] = m_mipv4->GetAddress(i, 0);  ///map的socket Address

    canRunMolsr = true;
  }

  if (canRunMolsr)
  {
    ///////xtt----molsr
    MclaimTimerExpire();
    SourceTimerExpire();
    ConfirmTimerExpire();
    //   LeaveTimerExpire ();

    NS_LOG_DEBUG("MOLSR on node " << m_mainAddress << " started");
  }
}
//设置主地址，，，molsr中如何设置呢， 没有使用该函数
void MulticastRoutingProtocol::SetMainInterface(uint32_t interface)
{
  //first interface address is main address
  m_mainAddress = m_mipv4->GetAddress(interface, 0).GetLocal();
}
////这个函数不用的，设置排除接口
void MulticastRoutingProtocol::SetInterfaceExclusions(std::set<uint32_t> exceptions)
{
  m_interfaceExclusions = exceptions;
}




// 产生一个MOLSR数据包用于传输消息。
void MulticastRoutingProtocol::RecvMolsr(Ptr<Socket> socket)
{

   NS_LOG_DEBUG("RecvMolsr" );
  Ptr<Packet> receivedPacket;
  ///这个源地址怎么获得？从socket中？
  Address sourceAddress;
  receivedPacket = socket->RecvFrom(sourceAddress);
  //计算接收开销和最后一个包的时间
  //recOverHead = recOverHead + receivedPacket->GetSize();
  //lastPktRecTime = Simulator::Now().GetSeconds();
  InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom(sourceAddress);
  //收发接口地址
  Ipv4Address senderIfaceAddr = inetSourceAddr.GetIpv4();

  Ipv4Address receiverIfaceAddr = m_socketAddresses[socket].GetLocal(); //接收接口地址

  NS_ASSERT(receiverIfaceAddr != Ipv4Address());
  NS_LOG_DEBUG("MOLSR node " << m_mainAddress << " received a MOLSR packet from "
                             << senderIfaceAddr << " to " << receiverIfaceAddr);

  // 检查端口号是不是发送的那个端口号。
  NS_ASSERT(inetSourceAddr.GetPort() == MOLSR_PORT_NUMBER);

  Ptr<Packet> packet = receivedPacket;
  //数据包头部   molsr
  molsr::PacketHeader molsrPacketHeader;
  //delete packet header 
  packet->RemoveHeader(molsrPacketHeader);
  //检查数据包长度是否大于头部长度
  NS_ASSERT(molsrPacketHeader.GetPacketLength() >= molsrPacketHeader.GetSerializedSize());
  uint32_t sizeLeft = molsrPacketHeader.GetPacketLength() - molsrPacketHeader.GetSerializedSize();

  MessageList messages;

  while (sizeLeft)
  {
    MessageHeader messageHeader;
    if (packet->RemoveHeader(messageHeader) == 0)
    {
      NS_ASSERT(false);
    }

    sizeLeft -= messageHeader.GetSerializedSize();

    NS_LOG_DEBUG("Molsr Msg received with type "
                 << std::dec << int(messageHeader.GetMessageType())
                 << " TTL=" << int(messageHeader.GetTimeToLive())
                 << " origAddr=" << messageHeader.GetOriginatorAddress());
    messages.push_back(messageHeader);
  }

  m_rxPacketTrace(molsrPacketHeader, messages);

  for (MessageList::const_iterator messageIter = messages.begin();
       messageIter != messages.end(); messageIter++)
  {
    const MessageHeader &messageHeader = *messageIter;
    //ttl<=0或者接收节点就是发送节点跳过
    if (messageHeader.GetTimeToLive() == 0
     || messageHeader.GetOriginatorAddress() == m_mainAddress)
    {
      packet->RemoveAtStart(messageHeader.GetSerializedSize() 
                                                      - messageHeader.GetSerializedSize());
      continue;
    }

    // If the message has been processed it must not be processed again
    bool do_forwarding = true;
    //find duplicate packet
    DuplicateTuple *duplicated = olsr->m_state.FindDuplicateTuple(messageHeader.GetOriginatorAddress(),
                                                            messageHeader.GetMessageSequenceNumber());

    if (duplicated == NULL)
    {
      switch (messageHeader.GetMessageType())
      {
      ///// mc_claim  没有携带信息怎么处理
      case molsr::MessageHeader::MC_CLAIM:
        NS_LOG_DEBUG(Simulator::Now().GetSeconds()
                     << "s MOLSR node " << m_mainAddress
                     << " received MC_CLAIM message of size " << messageHeader.GetSerializedSize());
        ProcessMclaim(messageHeader); //mc claim 只有数据包消息部分，包含主地址
        break;

      case molsr::MessageHeader::SOURCE_CLAIM:
        NS_LOG_DEBUG(Simulator::Now().GetSeconds()
                     << "s MOLSR node " << m_mainAddress
                     << " received SOURCE_CLAIM message of size " << messageHeader.GetSerializedSize());
        ProcessSource(messageHeader, senderIfaceAddr);
        break;

      case molsr::MessageHeader::CONFIRM_PARENT:
        NS_LOG_DEBUG(Simulator::Now().GetSeconds()
                     << "s MOLSR node " << m_mainAddress
                     << " received CONFIRM_PARENT message of size " << messageHeader.GetSerializedSize());
        ProcessConfirm(messageHeader, receiverIfaceAddr, senderIfaceAddr);
        break;
      case molsr::MessageHeader::LEAVE:
        NS_LOG_DEBUG(Simulator::Now().GetSeconds()
                     << "s MOLSR node " << m_mainAddress
                     << " received LEAVE message of size " << messageHeader.GetSerializedSize());
        ProcessLeave(messageHeader, receiverIfaceAddr, senderIfaceAddr);
        break;

      default:
        NS_LOG_DEBUG("MOLSR message type " << int(messageHeader.GetMessageType()) << " not implemented");
      }
    }
    else
    {
      NS_LOG_DEBUG("OLSR message is duplicated, not reading it.");

      // If the message has been considered for forwarding, it should
      // not be retransmitted again
      for (std::vector<Ipv4Address>::const_iterator it = duplicated->ifaceList.begin();
           it != duplicated->ifaceList.end(); it++)
      {
        if (*it == receiverIfaceAddr)
        {
          do_forwarding = false;
          break;
        }
      }
    }
    //消息转发，对于source消息用TC转发，对于claim和leave消息则单播给父节点
    if (do_forwarding)
    {
      //only forward
      // SOURCE  和  mc 都是和tc一样转发，其他两个消息要单播
      if (messageHeader.GetMessageType() == molsr::MessageHeader::CONFIRM_PARENT || messageHeader.GetMessageType() == molsr::MessageHeader::LEAVE)
      {
        ForwardToParent(messageHeader, duplicated,
                        receiverIfaceAddr, inetSourceAddr.GetIpv4());
      }
      else
      {
        olsr->ForwardDefault(messageHeader, duplicated,
                       receiverIfaceAddr, inetSourceAddr.GetIpv4());
      }
    }
  }
  MulticastRoutingTableComputation();
  ////////跟olsr的路由表，邻居表等都有关系。/////
}

Ipv4Address
MulticastRoutingProtocol::GetGroupAddr(Ipv4Address addr) const
{
  for (MulticastGroupSet::const_iterator mgrouptuple = olsr->m_state.GetGroupAddrSet().begin();
       mgrouptuple != olsr->m_state.GetGroupAddrSet().end(); mgrouptuple++)
  {
    if(mgrouptuple->NodeList.find(addr)!= mgrouptuple->NodeList.end()){
      return mgrouptuple->groupAddr;
    }
    
  }
  return NULL;
}

////////和olsr计算方法一样 using only the multicast routers
void MulticastRoutingProtocol::MulticastRoutingTableComputation()
{
  NS_LOG_DEBUG(Simulator::Now().GetSeconds() << " s: Node " << m_mainAddress
                                             << ": MulticastRoutingTableComputation begin...");

  //和olsr的计算方法一样
  //1.清空路由表
  Clear();

  // 2. 从一跳对称MC邻居开始作为目的节点
  const NeighborSet &neighborSet = olsr->m_state.GetNeighbors();
  for (NeighborSet::const_iterator it = neighborSet.begin();
       it != neighborSet.end(); it++)
  {
    NeighborTuple const &nb_tuple = *it;
    NS_LOG_DEBUG("Looking at neighbor tuple: " << nb_tuple);
    const McRouterTuple *mcRouter_tuple = olsr->m_state.FindMcRouterTuple(nb_tuple.neighborMainAddr); ////如果邻居是MC节点且是对称邻居
    if (mcRouter_tuple != NULL && nb_tuple.status == NeighborTuple::STATUS_SYM)
    {
      bool nb_main_addr = false;
      const LinkTuple *lt = NULL;
      const LinkSet &linkSet = olsr->m_state.GetLinks();
      for (LinkSet::const_iterator it2 = linkSet.begin(); it2 != linkSet.end(); it2++)
      {
        LinkTuple const &link_tuple = *it2;
        NS_LOG_DEBUG("Looking at link tuple: " << link_tuple << (link_tuple.time >= Simulator::Now() ? "" : " (expired)"));
        ///如果链路表中有该邻居，则存在该表项
        if ((olsr->GetMainAddress(link_tuple.neighborIfaceAddr) == nb_tuple.neighborMainAddr) && link_tuple.time >= Simulator::Now())
        {
          NS_LOG_LOGIC("Link tuple matches neighbor " << nb_tuple.neighborMainAddr
                                                      << " => adding routing table entry to neighbor");
          lt = &link_tuple;
          AddMulticastEntry(link_tuple.neighborIfaceAddr,
                            link_tuple.neighborIfaceAddr,
                            link_tuple.localIfaceAddr, 1);
          if (link_tuple.neighborIfaceAddr == nb_tuple.neighborMainAddr)
          {
            nb_main_addr = true;
          }
        }
        else
        {
          NS_LOG_LOGIC("Link tuple: linkMainAddress= " << olsr->GetMainAddress(link_tuple.neighborIfaceAddr)
                                                       << "; neighborMainAddr =  " << nb_tuple.neighborMainAddr
                                                       << "; expired=" << int(link_tuple.time < Simulator::Now())
                                                       << " => IGNORE");
        }
      }

      // If, in the above, no R_dest_addr is equal to the main
      // address of the neighbor, then another new routing entry
      // with MUST be added, with:
      //      MR_dest_addr  = main address of the neighbor;destination multicast capable node
      //      MR_next_addr  = L_neighbor_iface_addr of one of the   next hop multicast router in the route in the MC destination
      //                     associated link tuple with L_time >= current time;
      //      MR_dist       = 1;
      //      MR_iface_addr = L_local_iface_addr of the
      //                     associated link tuple.
      if (!nb_main_addr && lt != NULL)
      {
        NS_LOG_LOGIC("no R_dest_addr is equal to the main address of the neighbor "
                     "=> adding additional routing entry");
        AddMulticastEntry(nb_tuple.neighborMainAddr,
                          lt->neighborIfaceAddr,
                          lt->localIfaceAddr,
                          1);
      }
    }
  }
  //  3.对于严格两跳邻居,至少有一个邻居节点的willness不是never能到达该节点。,
  const TwoHopNeighborSet &twoHopNeighbors = olsr->m_state.GetTwoHopNeighbors();
  for (TwoHopNeighborSet::const_iterator it = twoHopNeighbors.begin();
       it != twoHopNeighbors.end(); it++)
  {
    TwoHopNeighborTuple const &nb2hop_tuple = *it;

    NS_LOG_LOGIC("Looking at two-hop neighbor tuple: " << nb2hop_tuple);
    const McRouterTuple *mcRouter_tuple = olsr->m_state.FindMcRouterTuple(nb2hop_tuple.twoHopNeighborAddr);
    // 该两跳邻居不是一跳邻居且不是自身

    if (olsr->m_state.FindSymNeighborTuple(nb2hop_tuple.twoHopNeighborAddr))
    {
      NS_LOG_LOGIC("Two-hop neighbor tuple is also neighbor; skipped.");
      continue;
    }

    if (nb2hop_tuple.twoHopNeighborAddr == m_mainAddress)
    {
      NS_LOG_LOGIC("Two-hop neighbor is self; skipped.");
      continue;
    }
    ///该两跳邻居是MC 节点
    if (mcRouter_tuple != NULL)
    {
      //至少有一个邻居节点的willness不是never能到达该节点。,
      bool nb2hopOk = false;
      ///不要求一跳邻居是MC节点，普通节点负责转发也
      for (NeighborSet::const_iterator neighbor = neighborSet.begin();
           neighbor != neighborSet.end(); neighbor++)
      {
        if (neighbor->neighborMainAddr == nb2hop_tuple.neighborMainAddr && neighbor->willingness != OLSR_WILL_NEVER)
        {
          nb2hopOk = true;
          break;
        }
      }
      if (!nb2hopOk)
      {
        NS_LOG_LOGIC("Two-hop neighbor tuple skipped: 2-hop neighbor "
                     << nb2hop_tuple.twoHopNeighborAddr
                     << " is attached to neighbor " << nb2hop_tuple.neighborMainAddr
                     << ", which was not found in the Neighbor Set.");
        continue;
      }

      // one selects one 2-hop tuple and creates one entry in the routing table with:
      //                R_dest_addr  =  the main address of the 2-hop neighbor;
      //                R_next_addr  = the R_next_addr of the entry in the
      //                               routing table with:
      //                                   R_dest_addr == N_neighbor_main_addr
      //                                                  of the 2-hop tuple;
      //                R_dist       = 2;
      //                R_iface_addr = the R_iface_addr of the entry in the
      //                               routing table with:
      //                                   R_dest_addr == N_neighbor_main_addr
      //                                                  of the 2-hop tuple;
      MulticastRoutingTableEntry entry;
      bool foundEntry = Lookup(nb2hop_tuple.neighborMainAddr, entry);
      if (foundEntry)
      {
        NS_LOG_LOGIC("Adding routing entry for two-hop neighbor.");
        AddMulticastEntry(nb2hop_tuple.twoHopNeighborAddr,
                          entry.MRnextAddr,
                          entry.MRinterface,
                          2);
      }
      else
      {
        NS_LOG_LOGIC("NOT adding routing entry for two-hop neighbor ("
                     << nb2hop_tuple.twoHopNeighborAddr
                     << " not found in the routing table)");
      }
    }
  }

  for (uint32_t h = 2;; h++)
  {
    bool added = false;

    // 3.1. For each topology entry in the topology table, if its
    // T_dest_addr does not correspond to R_dest_addr of any
    // route entry in the routing table AND its T_last_addr
    // corresponds to R_dest_addr of a route entry whose R_dist
    // is equal to h, then a new route entry MUST be recorded in
    // the routing table (if it does not already exist)
    const TopologySet &topology = olsr->m_state.GetTopologySet();
    for (TopologySet::const_iterator it = topology.begin();
         it != topology.end(); it++)
    {
      const TopologyTuple &topology_tuple = *it;
      NS_LOG_LOGIC("Looking at topology tuple: " << topology_tuple);

      MulticastRoutingTableEntry destAddrEntry, lastAddrEntry;
      bool have_destAddrEntry = Lookup(topology_tuple.destAddr, destAddrEntry);
      bool have_lastAddrEntry = Lookup(topology_tuple.lastAddr, lastAddrEntry);
      if (!have_destAddrEntry && have_lastAddrEntry && lastAddrEntry.MRdistance == h)
      {
        NS_LOG_LOGIC("Adding routing table entry based on the topology tuple.");
        // then a new route entry MUST be recorded in
        //                the routing table (if it does not already exist) where:
        //                     R_dest_addr  = T_dest_addr;
        //                     R_next_addr  = R_next_addr of the recorded
        //                                    route entry where:
        //                                    R_dest_addr == T_last_addr
        //                     R_dist       = h+1; and
        //                     R_iface_addr = R_iface_addr of the recorded
        //                                    route entry where:
        //                                       R_dest_addr == T_last_addr.
        AddMulticastEntry(topology_tuple.destAddr,
                          lastAddrEntry.MRnextAddr,
                          lastAddrEntry.MRinterface,
                          h + 1);
        added = true;
      }
      else
      {
        NS_LOG_LOGIC("NOT adding routing table entry based on the topology tuple: "
                     "have_destAddrEntry="
                     << have_destAddrEntry
                     << " have_lastAddrEntry=" << have_lastAddrEntry
                     << " lastAddrEntry.distance=" << (int)lastAddrEntry.MRdistance
                     << " (h=" << h << ")");
      }
    }

    if (!added)
    {
      break;
    }
  }

  // 4. For each entry in the multiple interface association base
  // where there exists a routing entry such that:
  // R_dest_addr == I_main_addr (of the multiple interface association entry)
  // AND there is no routing entry such that:
  // R_dest_addr == I_iface_addr
  const IfaceAssocSet &ifaceAssocSet = olsr->m_state.GetIfaceAssocSet();
  for (IfaceAssocSet::const_iterator it = ifaceAssocSet.begin();
       it != ifaceAssocSet.end(); it++)
  {
    IfaceAssocTuple const &tuple = *it;
    MulticastRoutingTableEntry entry1, entry2;
    bool have_entry1 = Lookup(tuple.mainAddr, entry1);
    bool have_entry2 = Lookup(tuple.ifaceAddr, entry2);
    if (have_entry1 && !have_entry2)
    {
      // then a route entry is created in the routing table with:
      //       R_dest_addr  =  I_iface_addr (of the multiple interface
      //                                     association entry)
      //       R_next_addr  =  R_next_addr  (of the recorded route entry)
      //       R_dist       =  R_dist       (of the recorded route entry)
      //       R_iface_addr =  R_iface_addr (of the recorded route entry).
      AddMulticastEntry(tuple.ifaceAddr,
                        entry1.MRnextAddr,
                        entry1.MRinterface,
                        entry1.MRdistance);
    }
  }

  // 5. 没有子网掩码问题

  NS_LOG_DEBUG("Node " << m_mainAddress << ": MulticastRoutingTableComputation end.");
  m_multicastRoutingTableChanged(GetSize());
  //m_neighborSetChanged (GetObject<Node> (), olsr->m_state.GetNeighbors ());
}


////使用状态类的insert函数。？？？？？？？？？？？  加入组播组////////////
void MulticastRoutingProtocol::AddMulticastGroup(Ipv4Address groupAddr)
{
 
    GroupAssocTuple *mgroup_tuple = olsr->m_state.FindGroupAssocTuple(groupAddr);
    if(mgroup_tuple == NULL){
      GroupAssocTuple tuple;
      tuple.groupAddr = groupAddr;
      tuple.NodeList.insert(m_mainAddress);
      olsr->m_state.InsertGroupAssocTuple(tuple);    
    }else
    {
      //如果组播组元组已经存在则只增加节点地址信息。
      mgroup_tuple->NodeList.insert(m_mainAddress);
    }
 
  olsr->IncrementAnsn();
}


void MulticastRoutingProtocol::AddMcRouterTuple(const McRouterTuple &tuple)
{

  olsr->m_state.InsertMcRouterTuple(tuple);
  olsr->IncrementAnsn();
}

void MulticastRoutingProtocol::RemoveMcRouterTuple(const McRouterTuple &tuple)
{
  olsr->m_state.EraseMcRouterTuple(tuple);
  olsr->IncrementAnsn();
}

void MulticastRoutingProtocol::AddMcTreeTuple(const McTreeTuple &tuple)
{

  olsr->m_state.InsertMcTreeTuple(tuple);
  olsr->IncrementAnsn();
}

void MulticastRoutingProtocol::RemoveMcTreeTuple(const McTreeTuple &tuple)
{
  olsr->m_state.EraseMcTreeTuple(tuple);
  olsr->IncrementAnsn();
}

/////填充mc  router table
void MulticastRoutingProtocol::ProcessMclaim(const molsr::MessageHeader &msg)
{
  const molsr::MessageHeader::Mclaim &mclaim = msg.GetMclaim(); ///获取到该消息

  Time now = Simulator::Now();
  // 1.如果发送节点不是组播路由器表里上的，就新增，否则就更新时间
  McRouterTuple *mcRouter_tuple = olsr->m_state.FindMcRouterTuple(msg.GetOriginatorAddress());
  if (mcRouter_tuple != NULL)
  {
    mcRouter_tuple->expirationTime = now + msg.GetVTime();
  }
  else
  {
    //建立mc router 表格
    McRouterTuple mcrouterTuple;
    mcrouterTuple.MmAddr = msg.GetOriginatorAddress();
    mcrouterTuple.sequenceNumber = mclaim.ansn;
    mcrouterTuple.expirationTime = now + msg.GetVTime();
    AddMcRouterTuple(mcrouterTuple);
    NS_LOG_DEBUG("process mc_claim");
    m_events.Track(Simulator::Schedule(DELAY(mcrouterTuple.expirationTime),
                                       &MulticastRoutingProtocol::McRouterTupleTimerExpire,
                                       this,
                                       mcrouterTuple.MmAddr));
  }
}

void MulticastRoutingProtocol::ProcessSource(const molsr::MessageHeader &msg,
                                             const Ipv4Address &senderIfaceAddr)
{
  const molsr::MessageHeader::Sourceclaim &sourceclaim = msg.GetSourceclaim();
  Time now = Simulator::Now();
  ///1.查询表中有没有树，没有就新增，有就更新时间
  McTreeTuple *mctreeTuple =
      olsr->m_state.FindMcTreeTuple(msg.GetOriginatorAddress(), sourceclaim.multicastGroupAddress);
  if (mctreeTuple != NULL)
  {
    mctreeTuple->mtsourceTime = now + msg.GetVTime();
  }
  else
  {
    // 4.2. 新增XTT---MOLSR
    McTreeTuple mctreeTuple;
    mctreeTuple.mtgroupAddr = sourceclaim.multicastGroupAddress;
    mctreeTuple.mtsourceAddr = msg.GetOriginatorAddress();
    mctreeTuple.mtsourceTime = SOURCE_HOLD_TIME;
    mctreeTuple .sequenceNumber = sourceclaim.ansn;
        //将父子信息设置为null，不设置？？？
    mctreeTuple.mtchildList .clear();
    AddMcTreeTuple(mctreeTuple);

//send a confirm_parent to its parent
    SendConfirm();
    ///////////////发送一个confirm消息给父亲节点???????
    // 过期就删除
    m_events.Track(Simulator::Schedule(DELAY(mctreeTuple.mtsourceTime),
                                       &MulticastRoutingProtocol::McTreeTupleTimerExpire,
                                       this,
                                       mctreeTuple.mtsourceAddr,
                                       mctreeTuple.mtgroupAddr));
 }
}
//
void MulticastRoutingProtocol::ProcessConfirm(const molsr::MessageHeader &msg,
                                              const Ipv4Address &receiverIfaceAddr,
                                              const Ipv4Address &senderIfaceAddr)
{
  const molsr::MessageHeader::Confirmparent &confirmparent = msg.GetConfirmparent();
  Time now = Simulator::Now();
  // 1.如果发送节点不是对称链路上的，就丢弃,,confirm有多组信息
  for (std::vector<molsr::MessageHeader::Confirmparent::Group>::const_iterator it = confirmparent.group.begin();
       it != confirmparent.group.end(); it++)
  {
     McTreeTuple *mctreeTuple =
        olsr->m_state.FindMcTreeTuple(msg.GetOriginatorAddress(), it->multicastGroupAddress);
    if (mctreeTuple == NULL)
    {
      McTreeTuple mctreeTuple;
      mctreeTuple.mtgroupAddr = it->multicastGroupAddress;
      mctreeTuple.mtsourceAddr = msg.GetOriginatorAddress();
      mctreeTuple.mtsourceTime = SOURCE_HOLD_TIME;
      //ansn???
      mctreeTuple.mtchildList .clear();
      AddMcTreeTuple(mctreeTuple);
    }
    else
    {
      mctreeTuple->mtsourceTime = SOURCE_HOLD_TIME;
      //if son addreaa does exits in the son list,update mt_son_time else create a new record for this son 
      if (mctreeTuple->mtchildList.find(senderIfaceAddr)!=mctreeTuple->mtchildList.end())
      {
        mctreeTuple->mtchildTime = now + SON_HOLD_TIME;
      }
      else
      {
        //set mt_son_addr to the originator address of the confirm_parent msg.
        mctreeTuple->mtchildList.insert(msg.GetOriginatorAddress());
        mctreeTuple->mtchildTime = now + SON_HOLD_TIME;
      }

      if (mctreeTuple->mtparentAddr == NULL)
      {
        //set mt_parent_addr to the next hop(MR_next)in the multicast routing table of the current node to te source
        std::map<Ipv4Address, MulticastRoutingTableEntry>::const_iterator it = m_mtable.find(receiverIfaceAddr);
        mctreeTuple->mtparentAddr = it->second.MRnextAddr;
      }
    }
    // 过期就删除
    m_events.Track(Simulator::Schedule(DELAY(mctreeTuple->mtsourceTime),
                                       &MulticastRoutingProtocol::McTreeTupleTimerExpire,
                                       this,
                                       mctreeTuple->mtsourceAddr,
                                       mctreeTuple->mtgroupAddr));
  }
}

void MulticastRoutingProtocol::ProcessLeave(const molsr::MessageHeader &msg,
                                            const Ipv4Address &receiverIfaceAddr,
                                            const Ipv4Address &senderIfaceAddr)
{
  const molsr::MessageHeader::Leave &leave = msg.GetLeave();
  Time now = Simulator::Now();
  // 1.如果发送节点不是对称链路上的，就丢弃,,confirm有多组信息
  for (std::vector<molsr::MessageHeader::Leave::Group>::const_iterator it = leave.group.begin();
       it != leave.group.end(); it++)
  {
   McTreeTuple *mctreeTuple =
        olsr->m_state.FindMcTreeTuple(msg.GetOriginatorAddress(), it->multicastGroupAddress);
    if (mctreeTuple != NULL)
    {
      //如果存在该叶子节点的树,则删除叶子节点.更新时间.再判断父节点是不是组播节点,如果不是也删除.
      mctreeTuple->mtchildList.erase(senderIfaceAddr);
      mctreeTuple->mtchildTime = now + SON_HOLD_TIME;
      //if its parent becomes a leaf, this parent is not a group member .it detached itself from the tree on its turn .
      std::map<Ipv4Address, MulticastRoutingTableEntry>::const_iterator it = m_mtable.find(receiverIfaceAddr);
      const McRouterTuple *mcRoutertuple = olsr->m_state.FindMcRouterTuple(it->second.MRnextAddr);
      if (mcRoutertuple == NULL)
      {
        ///该父节点 不是组播节点，则删除该叶子节点。
        mctreeTuple->mtchildList.erase(it->second.MRnextAddr);
      }
    }
    else
    {
      continue;
    }
    // 过期就删除
    m_events.Track(Simulator::Schedule(DELAY(mctreeTuple->mtsourceTime),
                                       &MulticastRoutingProtocol::McTreeTupleTimerExpire,
                                       this,
                                       mctreeTuple->mtsourceAddr,
                                       mctreeTuple->mtgroupAddr));
  }
}

//unicast forward to its parent for confirm and leave msg
void MulticastRoutingProtocol::ForwardToParent(molsr::MessageHeader molsrMessage,
                                               DuplicateTuple *duplicated,
                                               const Ipv4Address &localIface,
                                               const Ipv4Address &senderAddress)
{
  Time now = Simulator::Now();
  int numMessages = 0;
  Ptr<Packet> packet = Create<Packet> ();
  //////判断是否重传了,如果重传了就丢弃
  if (duplicated != NULL && duplicated->retransmitted)
  {
    NS_LOG_LOGIC(Simulator::Now() << "Node " << m_mainAddress << " does not forward a message received"
                                                                 " from "
                                  << molsrMessage.GetOriginatorAddress() << " because it is duplicated");
    return;
  }
  bool retransmitted = false;
  if (molsrMessage.GetTimeToLive() > 1)
  {
      QueueMessage (molsrMessage, JITTER);
      retransmitted = true;
  }
  // Update duplicate tuple...
  if (duplicated != NULL)
  {
    duplicated->expirationTime = now + MOLSR_DUP_HOLD_TIME;
    duplicated->retransmitted = retransmitted;
    duplicated->ifaceList.push_back(localIface);
  }
  // ...or create a new one
  else
  {
    DuplicateTuple newDup;
    newDup.address = molsrMessage.GetOriginatorAddress();
    newDup.sequenceNumber = molsrMessage.GetMessageSequenceNumber();
    newDup.expirationTime = now + MOLSR_DUP_HOLD_TIME;
    newDup.retransmitted = retransmitted;
    newDup.ifaceList.push_back(localIface);
    olsr->AddDuplicateTuple(newDup);
    // Schedule dup tuple deletion
    Simulator::Schedule(MOLSR_DUP_HOLD_TIME,
                        &MulticastRoutingProtocol::DupTupleTimerExpire, this,
                        newDup.address, newDup.sequenceNumber);
    ///pointer to member type ‘void (ns3::molsr::RoutingProtocol::)(ns3::Ipv4Address,
    ////short unsigned int)’ incompatible with object type ‘ns3::molsr::MulticastRoutingProtocol
  }
}


void
MulticastRoutingProtocol::DupTupleTimerExpire (Ipv4Address address, uint16_t sequenceNumber)
{
  DuplicateTuple *tuple =
    olsr->m_state.FindDuplicateTuple (address, sequenceNumber);
  if (tuple == NULL)
    {
      return;
    }
  if (tuple->expirationTime < Simulator::Now ())
    {
      olsr->RemoveDuplicateTuple (*tuple);
    }
  else
    {
      m_events.Track (Simulator::Schedule (DELAY (tuple->expirationTime),
                                           &MulticastRoutingProtocol::DupTupleTimerExpire, this,
                                           address, sequenceNumber));
    }
}

//distinguish unicast or mpr
void MulticastRoutingProtocol::SendMclaim()
{
  NS_LOG_FUNCTION(this);

  molsr::MessageHeader msg;

  msg.SetVTime(MC_HOLD_TIME);
  msg.SetOriginatorAddress(m_mainAddress);
  msg.SetTimeToLive(255);
  msg.SetHopCount(0);
  msg.SetMessageSequenceNumber(GetMessageSequenceNumber());

  molsr::MessageHeader::Mclaim &mclaim = msg.GetMclaim();
  mclaim.ansn = m_ansn;
  //use MPR flood msg
  for (MprSelectorSet::const_iterator mprsel_tuple = olsr->m_state.GetMprSelectors().begin();
       mprsel_tuple != olsr->m_state.GetMprSelectors().end(); mprsel_tuple++)
  {
    mclaim.neighborAddresses.push_back(mprsel_tuple->mainAddr);
  }
  QueueMessage(msg, JITTER); //发送消息
  NS_LOG_DEBUG("Queue mc_claim");
}

///传入组播地址 按照TC转发
void MulticastRoutingProtocol::SendSource()
{
  NS_LOG_FUNCTION(this);

  molsr::MessageHeader msg;

  msg.SetVTime(SOURCE_HOLD_TIME);

  msg.SetOriginatorAddress(m_mainAddress);
  msg.SetTimeToLive(255);
  msg.SetHopCount(0);
  msg.SetMessageSequenceNumber(GetMessageSequenceNumber());

  molsr::MessageHeader::Sourceclaim &sourceclaim = msg.GetSourceclaim();
  ////////组播组地址应该是什么？？？？？？？？？组播ip地址识别组播组，那发送节点的ip地址作为组播组地址？

  ///判断   信源集合是否位空，，加一个信源集合和心宿集合
  //如果在信源集合中，则发送sourceclaim
  // for (std::vector<Ipv4Address>::const_iterator iter = SourceSet.begin();
  //      iter != SourceSet.end(); iter++){
  //        if (iter->Get() != m_mainAddress)){}
  //      }
  if (SourceSet.find(m_mainAddress) != SourceSet.end())
  {
    ///组播组地址 利用源地址判断属于哪个组播组，得到组播组地址//添加组播组地址????
    sourceclaim.multicastGroupAddress = GetGroupAddr(m_mainAddress); 
    for (MprSelectorSet::const_iterator mprsel_tuple = olsr->m_state.GetMprSelectors().begin();
         mprsel_tuple != olsr->m_state.GetMprSelectors().end(); mprsel_tuple++)
    {
      sourceclaim.neighborAddresses.push_back(mprsel_tuple->mainAddr) ;
    }
    QueueMessage(msg, JITTER);
  }
  NS_LOG_DEBUG("Queue SOURCE");
}
//////////单播,when send this msg？
void MulticastRoutingProtocol::SendConfirm()
{
  NS_LOG_FUNCTION(this);

  molsr::MessageHeader msg;

  msg.SetVTime(SON_HOLD_TIME);
  msg.SetOriginatorAddress(m_mainAddress); ////发送confirm的节点地址
  msg.SetTimeToLive(255);
  msg.SetHopCount(0);
  msg.SetMessageSequenceNumber(GetMessageSequenceNumber());
  ///获取消息中source消息  /////如何获取自己收到的sourceclaim消息的内容???????????????????????????????????????????????????????????????
  // molsr::MessageHeader::Sourceclaim &sourceclaim = msg.GetSourceclaim();

  molsr::MessageHeader::Confirmparent &confirmparent = msg.GetConfirmparent();
  std::vector<molsr::MessageHeader::Confirmparent::Group> &groups = confirmparent.group;
  Ipv4Address groupAddr = GetGroupAddr(m_mainAddress);
  //if there is entry in multicastroutingtable ,find its parent
  std::map<Ipv4Address, MulticastRoutingTableEntry>::const_iterator it = m_mtable.find(m_mainAddress);
  //判断是否属于某个组播组或者有没有转发表
  if (it == m_mtable.end()||groupAddr == NULL)
  {
    return;
  }
  ///////////confirm 消息的地址怎么获得？
  molsr::MessageHeader::Confirmparent::Group group;
  ////////父亲地址是多播路由表中的mr_next。需要设置接口地址????怎么设置?????
  group.parentAddresses = it->second.MRnextAddr;
  group.multicastGroupAddress = groupAddr;
  group.multicastSourceAddress = m_mainAddress;
  groups.push_back(group);

  QueueMessage(msg, JITTER);
  NS_LOG_DEBUG("Queue Confirm");
}

void MulticastRoutingProtocol::SendLeave()
{
  NS_LOG_FUNCTION(this);

  molsr::MessageHeader msg;

  msg.SetVTime(LEAVE_HOLD_TIME);
  msg.SetOriginatorAddress(m_mainAddress);
  msg.SetTimeToLive(255);
  msg.SetHopCount(0);
  msg.SetMessageSequenceNumber(GetMessageSequenceNumber());

  //??????????????????????????????????????????????
  // molsr::MessageHeader::Sourceclaim &sourceclaim = msg.GetSourceclaim();
  molsr::MessageHeader::Leave &leave = msg.GetLeave();
  std::vector<molsr::MessageHeader::Leave::Group> &groups = leave.group;
  ///////////confirm 消息的地址怎么获得？
  Ipv4Address groupAddr = GetGroupAddr(m_mainAddress);
  molsr::MessageHeader::Leave::Group group;
  std::map<Ipv4Address, MulticastRoutingTableEntry>::const_iterator it = m_mtable.find(m_mainAddress);
  if (it == m_mtable.end()||groupAddr == NULL)
  {
    return;
  }
  ////////父亲地址是多播路由表中的mr_next。需要设置接口地址????怎么设置?????
  group.parentAddresses = it->second.MRnextAddr;
  /////由source消息知道组播组地址和源地址
  group.multicastGroupAddress = groupAddr;
  group.multicastSourceAddress = m_mainAddress;
  groups.push_back(group);

  QueueMessage(msg, JITTER);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////组播不区分主机号和网络号，没有子网掩码

//和iov4的关联  xtttmolsr
/*
void MulticastRoutingProtocol::AddDuplicateTuple(const DuplicateTuple &tuple)
{
  olsr->m_state.InsertDuplicateTuple(tuple);
}

void MulticastRoutingProtocol::RemoveDuplicateTuple(const DuplicateTuple &tuple)
{
  olsr->m_state.EraseDuplicateTuple(tuple);
}

void MulticastRoutingProtocol::AddIfaceAssocTuple(const IfaceAssocTuple &tuple)
{
  olsr->m_state.InsertIfaceAssocTuple(tuple);
}

void MulticastRoutingProtocol::RemoveIfaceAssocTuple(const IfaceAssocTuple &tuple)
{
  olsr->m_state.EraseIfaceAssocTuple(tuple);
}
*/
uint16_t MulticastRoutingProtocol::GetPacketSequenceNumber()
{
  m_packetSequenceNumber = (m_packetSequenceNumber + 1) % (MOLSR_MAX_SEQ_NUM + 1);
  return m_packetSequenceNumber;
}

uint16_t MulticastRoutingProtocol::GetMessageSequenceNumber()
{
  m_messageSequenceNumber = (m_messageSequenceNumber + 1) % (MOLSR_MAX_SEQ_NUM + 1);
  return m_messageSequenceNumber;
}

/////////XTTmolsr
void MulticastRoutingProtocol::MclaimTimerExpire()
{
  //if (olsr->m_state.GetMprSelectors().size() > 0)
 // {
    //r如果是发送节点直接发
    SendMclaim();
    //接收的时候判断自己是否被选为MPR，有则转发。
  //}
 // else
 /// {
 //   NS_LOG_DEBUG("Not sending any MC_CLAIM, no one selected me as MPR.");
  //}
   NS_LOG_DEBUG("send mc_claim");
  m_mclaimTimer.Schedule(m_mclaimInterval);
}

void MulticastRoutingProtocol::SourceTimerExpire()
{
  //mpr is not null & node is source
  if (olsr->m_state.GetMprSelectors().size() > 0)
  {
    /////////获取组播地址，在state中写
    // for (MulticastGroupSet::const_iterator mgroup_tuple = olsr->m_state.GetGroupAddrSet().begin();
    //      mgroup_tuple != olsr->m_state.GetGroupAddrSet().end(); mgroup_tuple++)
    //   {

    //     SendSource();
    //   }
    NS_LOG_DEBUG("Send Source_Claim");
    SendSource();
  }
  else
  {
    NS_LOG_DEBUG("Not sending any SOURCE CLAIM, no one selected me as MPR.");
  }
  m_sourceclaimTimer.Schedule(m_sourceInterval);
}
////只有自己是组播组成员才会发送确认信息.,,,,,,,看aodv
void MulticastRoutingProtocol::ConfirmTimerExpire()
{
  if (olsr->m_state.GetMcTreeSet().size() > 0)
  {
    // SendConfirm(olsr->m_state->GetGroupAddr());
    SendConfirm();
  }
  else
  {
    NS_LOG_DEBUG("Not sending any CONFIRM, i am not in any multicast group.");
  }
  m_confirmparentTimer.Schedule(m_confirmInterval);
}
/*
void
MulticastRoutingProtocol::LeaveTimerExpire ()
{
if a node want to leave the tree,how to know it wanna to leave ?
bool leave = false;

}*/


void MulticastRoutingProtocol::Clear()
{
  NS_LOG_FUNCTION_NOARGS();
  m_mtable.clear();
}

void MulticastRoutingProtocol::RemoveMulticastEntry(Ipv4Address const &MRdest)
{
  m_mtable.erase(MRdest);
}

bool MulticastRoutingProtocol::Lookup(Ipv4Address const &MRdest,
                                      MulticastRoutingTableEntry &outEntry) const
{
  // Get the iterator at "dest" position
  std::map<Ipv4Address, MulticastRoutingTableEntry>::const_iterator it = m_mtable.find(MRdest);
  // If there is no route to "dest", return NULL
  if (it == m_mtable.end())
  {
    return false;
  }
  outEntry = it->second;
  return true;
}

bool MulticastRoutingProtocol::FindSendEntry(MulticastRoutingTableEntry const &entry,
                                             MulticastRoutingTableEntry &outEntry) const
{
  outEntry = entry;
  while (outEntry.MRdestAddr != outEntry.MRnextAddr)
  {
    if (not Lookup(outEntry.MRnextAddr, outEntry))
    {
      return false;
    }
  }
  return true;
}
int MulticastRoutingProtocol::MulticastJoinGroup(Ipv4Address groupAddr, bool src, bool dst)
{
  // const McRouterTuple *mcRouter_tuple1 = olsr->m_state.FindMcRouterTuple (neighbor->neighborMainAddr);
  //获取molsr指针，对其添加groupAddress,设置信源信宿. 当是信源的时候创建组播树，新宿的话就维护组播树
  if (src)
  {
     AddMulticastGroup(groupAddr);
    SendSource();
    return 0;
  }
  else if (dst)
  {
    AddMulticastGroup(groupAddr);
    SendConfirm();

  }
  return -1;
}
//////将组播地址重置为0.  sendLeave?
int MulticastRoutingProtocol::MulticastLeaveGroup(Ipv4Address groupAddr)
{
  // EraseGroupAssocTuple
  GroupAssocTuple *mgroup_tuple = olsr->m_state.FindGroupAssocTuple(groupAddr);
  if (mgroup_tuple != NULL)
  {
    mgroup_tuple->NodeList.erase(m_mainAddress);
    return 0;
  }
  return -1;
}

////////////
Ptr<Ipv4Route>
MulticastRoutingProtocol::RouteOutput(Ptr<Packet> p, const Ipv4Header &header, Ptr<NetDevice> oif, Socket::SocketErrno &sockerr)
{
  
  NS_LOG_FUNCTION(this << " " << m_mipv4->GetObject<Node>()->GetId() << " " << header.GetDestination() << " " << oif);

  //if (p->GetSize() >= 512)
    //sentPackets += 1;

  //m_helloInterval = Seconds(1); 	//hans proposal
  //mrtentry
 
   Ptr<Ipv4Route> rtentry;
 
    //  rtentry->SetOutputDevice (m_mipv4->GetNetDevice (interfaceIdx));
  Ptr<Ipv4MulticastRoute> mrtentry ;
  MulticastRoutingTableEntry entry1, entry2;
  bool found = false;
  ////////查找路由表，ip目的地址  传给entry1
  if (Lookup(header.GetDestination(), entry1) != 0)
  {
    ////查找转发表
    bool foundSendEntry = FindSendEntry(entry1, entry2);
    if (!foundSendEntry)
    {
      NS_FATAL_ERROR("FindSendEntry failure");
    }
    uint32_t interfaceIdx = entry2.MRinterface;
    
    /////如果转发表的接口地址不等于设备的接口，则不能转发
    if (oif && m_mipv4->GetInterfaceForDevice(oif) != static_cast<int>(interfaceIdx))
    {
      // We do not attempt to perform a constrained routing search
      // if the caller specifies the oif; we just enforce that
      // that the found route matches the requested outbound interface
      NS_LOG_DEBUG("MOlsr node " << m_mainAddress
                                 << ": RouteOutput for dest=" << header.GetDestination()
                                 << " Route interface " << interfaceIdx
                                 << " does not match requested output interface "
                                 << m_mipv4->GetInterfaceForDevice(oif));
      sockerr = Socket::ERROR_NOROUTETOHOST;
      // dropCount +=1;
      return rtentry;
      /////////转为ipv4multicastroute？？？？？？？？？？？？？？？？？？？？？？？？？
    }
    /////创建一个组播路由，设置组地址，源地址和父节点地址，转发。
    mrtentry = Create<Ipv4MulticastRoute>();
    ///
    mrtentry->SetGroup(header.GetDestination()); ///////组地址就是目的地址
    // the source address is the interface address that matches
    // the destination address (when multiple are present on the
    // outgoing interface, one is selected via scoping rules)
    NS_ASSERT(m_mipv4);
    uint32_t numOifAddresses = m_mipv4->GetNAddresses(interfaceIdx); ////计算接口地址数
    NS_ASSERT(numOifAddresses > 0);
    ///将接口地址第一个接口的主地址设为源地址
    Ipv4InterfaceAddress ifAddr;
    if (numOifAddresses == 1)
    {
      ifAddr = m_mipv4->GetAddress(interfaceIdx, 0);
    }
    else
    {
      /// \todo Implment IP aliasing and OLSR
      NS_FATAL_ERROR("XXX Not implemented yet:  IP aliasing and OLSR");
    }
    rtentry = new Ipv4Route();
    rtentry->SetDestination (header.GetDestination());
    rtentry->SetGateway ("0.0.0.0");
    rtentry->SetSource (ifAddr.GetLocal ());
    rtentry->SetOutputDevice (m_mipv4->GetNetDevice (interfaceIdx));
    
    mrtentry->SetOrigin(ifAddr.GetLocal());
    mrtentry->SetParent(interfaceIdx);
    mrtentry->SetOutputTtl(interfaceIdx,header.GetTtl());

    sockerr = Socket::ERROR_NOTERROR;
    NS_LOG_DEBUG("MOlsr node " << m_mainAddress
                               << ": RouteOutput for group=" << header.GetDestination()
                               << " --> parent=" << entry2.MRnextAddr
                               << " interface=" << entry2.MRinterface);
    found = true;
  }
  else
  {
    //   rtentry = m_hnaRoutingTable->RouteOutput (p, header, oif, sockerr);

    if (mrtentry)
    {
      found = true;
      //      NS_LOG_DEBUG ("Found route to " << rtentry->GetDestination () << " via nh " << rtentry->GetGateway () << " with source addr " << rtentry->GetSource () << " and output dev " << rtentry->GetOutputDevice ());
    }
  }

  if (!found)
  {
    NS_LOG_DEBUG("MOlsr node " << m_mainAddress
                               << ": RouteOutput for group=" << header.GetDestination()
                               << " No route to host");
    sockerr = Socket::ERROR_NOROUTETOHOST;
   // dropCount += 1; //记录丢包
  }
  
  return rtentry;
  
}


bool MulticastRoutingProtocol::RouteInput(Ptr<const Packet> p,
                                          const Ipv4Header &header, Ptr<const NetDevice> idev,
                                          UnicastForwardCallback ucb, MulticastForwardCallback mcb,
                                          LocalDeliverCallback lcb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION(this << " " << m_mipv4->GetObject<Node>()->GetId() << " " << header.GetDestination());

  Ipv4Address dst = header.GetDestination();
  Ipv4Address origin = header.GetSource();

  // Consume self-originated packets
  if (IsMyOwnAddress(origin) == true)
  {
    return true;
  }

  // Local delivery
  NS_ASSERT(m_mipv4->GetInterfaceForDevice(idev) >= 0);
  uint32_t iif = m_mipv4->GetInterfaceForDevice(idev);
  if (m_mipv4->IsDestinationAddress(dst, iif))
  {
    if (!lcb.IsNull())
    {
      NS_LOG_LOGIC("Local delivery to " << dst);
      lcb(p, header, iif);
      return true;
    }
    else
    {

      // The local delivery callback is null.  This may be a multicast
      // or broadcast packet, so return false so that another
      // multicast routing protocol can handle it.  It should be possible
      // to extend this to explicitly check whether it is a unicast
      // packet, and invoke the error callback if so

      ///需要lcb往上层送，，，lcb和mcb的参数不一样，在ipv4L3PROTOCOL

      //  mcb ( p, header, iif);/////////ipv4l3     ip
      return false;
    }
  }

  // 查找转发路由表
  Ptr<Ipv4MulticastRoute> mrtentry;
  MulticastRoutingTableEntry entry1, entry2;
  if (Lookup(header.GetDestination(), entry1))
  {
    //发现路由表，查找转发表
    bool foundSendEntry = FindSendEntry(entry1, entry2);
    if (!foundSendEntry)
    {
      NS_FATAL_ERROR("FindSendEntry failure");
    }
    mrtentry = Create<Ipv4MulticastRoute> ();
   // rtentry->SetGroup(header.GetDestination()); ///////////设置组地址
    //mrtentry->SetDestination (header.GetDestination ());
    uint32_t interfaceIdx = entry2.MRinterface;
    // the source address is the interface address that matches
    // the destination address (when multiple are present on the
    // outgoing interface, one is selected via scoping rules)
    NS_ASSERT(m_mipv4);
    uint32_t numOifAddresses = m_mipv4->GetNAddresses(interfaceIdx);//接口总数
    NS_ASSERT(numOifAddresses > 0);
    Ipv4InterfaceAddress ifAddr;
    if (numOifAddresses == 1)
    {
      ifAddr = m_mipv4->GetAddress(interfaceIdx, 0);
    }
    else
    {

      /// \todo Implment IP aliasing and OLSR
      NS_FATAL_ERROR("XXX Not implemented yet:  IP aliasing and MOLSR");
    }
   
    Ptr<Ipv4MulticastRoute> mrtentry = Create<Ipv4MulticastRoute>();
     //RTENTRY按照ipmulticastforwad中的路由表项生成格式
    mrtentry->SetOrigin(ifAddr.GetLocal());
    mrtentry->SetParent(entry2.MRinterface);//接口地址
    mrtentry->SetOutputTtl(interfaceIdx,header.GetTtl());
    // rtentry->SetSource(header.GetSource());
    // rtentry->SetDestination(header.GetDestination());
    // rtentry->SetGateway(Ipv4Address::GetAny());
    // rtentry->SetOutputDevice(GetNetDevice(interfaceIdx));
    NS_LOG_DEBUG("MOlsr node " << m_mainAddress
                               << ": RouteInput for group=" << header.GetDestination()
                               << " -->parent=" << entry2.MRnextAddr
                               << " interface=" << entry2.MRinterface);
    ///组播转发回调
    mcb(mrtentry, p, header);
    return true;
  }
  else
  {

    //dropCount += 1;
    return false;
  }
}

void MulticastRoutingProtocol::McRouterTupleTimerExpire(const Ipv4Address MmAddr)
{

}
void MulticastRoutingProtocol::McTreeTupleTimerExpire(const Ipv4Address mtsourceAddr,
                              const Ipv4Address mtgroupAddr)
                              {

                              }
void
MulticastRoutingProtocol::QueueMessage (const molsr::MessageHeader &message, Time delay)
{
  m_queuedMessages.push_back (message);

      if (not m_queuedMessagesTimer.IsRunning ())
    {
      m_queuedMessagesTimer.SetDelay (delay);
      m_queuedMessagesTimer.Schedule ();
    }
  

}

void MulticastRoutingProtocol::SendQueuedMessages()
{
  Ptr<Packet> packet = Create<Packet> ();
  int numMessages = 0;

  NS_LOG_DEBUG ("Molsr node " << m_mainAddress << ": SendQueuedMessages");
//vector of message
  MessageList msglist;

  for (std::vector<molsr::MessageHeader>::const_iterator message = m_queuedMessages.begin ();
       message != m_queuedMessages.end ();
       message++)
    {
      ////message type
      if(message->GetMessageType() == 7 || message->GetMessageType() == 8)
      {
        //寻找parent地址
       const McTreeTuple *mctreeTuple =
       olsr->m_state.FindMcTreeTuple(message->GetOriginatorAddress(),GetGroupAddr(message->GetOriginatorAddress())); 
       Ipv4Address parentAddress = mctreeTuple->mtparentAddr;
        Ptr<Packet> p = Create<Packet> ();
        p->AddHeader (*message);
        packet->AddAtEnd (p);
        msglist.push_back (*message);
        if (++numMessages == MOLSR_MAX_MSGS)
        {
          SendPacketToParent (packet, msglist,parentAddress);
          msglist.clear ();
          // Reset variables for next packet
          numMessages = 0;
          packet = Create<Packet> ();
        }
      }else
      {
        Ptr<Packet> p = Create<Packet> ();
        p->AddHeader (*message);
        packet->AddAtEnd (p);
        msglist.push_back (*message);
        if (++numMessages == MOLSR_MAX_MSGS)
        {
          SendPacket (packet, msglist);
          msglist.clear ();
          // Reset variables for next packet
          numMessages = 0;
          packet = Create<Packet> ();
        }
      }
    }
  if (packet->GetSize ())
    {
      SendPacket (packet, msglist);
    }
  m_queuedMessages.clear ();
}




void
MulticastRoutingProtocol::SendPacket (Ptr<Packet> packet,
                             const MessageList &containedMessages)
{
  NS_LOG_DEBUG ("MOLSR node " << m_mainAddress << " sending a MOLSR packet");

  // Add a header
  molsr::PacketHeader header;
  header.SetPacketLength (header.GetSerializedSize () + packet->GetSize ());
  header.SetPacketSequenceNumber (GetPacketSequenceNumber ());
  packet->AddHeader (header);

  // Trace it
  m_txPacketTrace (header, containedMessages);

  // Send it
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i =
         m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
      Ptr<Packet> pkt = packet->Copy ();
      //10.255.255.255.a 类地址default 
      Ipv4Address bcast = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
      i->first->SendTo (packet, 0, InetSocketAddress (bcast, MOLSR_PORT_NUMBER));

    //  overHead = overHead + pkt->GetSize();//计算开销
    }
}

void
MulticastRoutingProtocol::SendPacketToParent (Ptr<Packet> packet,
                             const MessageList &containedMessages,Ipv4Address parentAddress)
{
  NS_LOG_DEBUG ("Send packet to Parent");

  // Add a header
  molsr::PacketHeader header;
  header.SetPacketLength (header.GetSerializedSize () + packet->GetSize ());
  header.SetPacketSequenceNumber (GetPacketSequenceNumber ());
  packet->AddHeader (header);
  // Trace it
  m_txPacketTrace (header, containedMessages);

  // Send it
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i =
         m_socketAddresses.begin (); i != m_socketAddresses.end (); i++)
    {
    //  Ptr<Packet> pkt = packet->Copy ();
      //10.255.255.255.a 类地址default 
     // Ipv4Address bcast = i->second.GetLocal ().GetSubnetDirectedBroadcast (i->second.GetMask ());
      i->first->SendTo (packet, 0, InetSocketAddress (parentAddress, MOLSR_PORT_NUMBER));
     NS_LOG_DEBUG ("Send packet to Parent");
    //  overHead = overHead + pkt->GetSize();//计算开销
    }
}
void MulticastRoutingProtocol::LeaveTimerExpire()
{

}
void MulticastRoutingProtocol::NotifyInterfaceUp(uint32_t i)
{
}
void MulticastRoutingProtocol::NotifyInterfaceDown(uint32_t i)
{
}
void MulticastRoutingProtocol::NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
}
void MulticastRoutingProtocol::NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
}
 void MulticastRoutingProtocol::PrintRoutingTable  (Ptr<OutputStreamWrapper> stream, Time::Unit unit )const 
 {
}

void MulticastRoutingProtocol::AddMulticastEntry(Ipv4Address const &MRdest,
                                                 Ipv4Address const &MRnext,
                                                 uint32_t interface,
                                                 uint32_t distance)
{
  NS_LOG_FUNCTION(this << MRdest << MRnext << interface << distance << m_mainAddress);
  NS_ASSERT(distance > 0);

  // Creates a new rt entry with specified values
  MulticastRoutingTableEntry &entry = m_mtable[MRdest];

  entry.MRdestAddr = MRdest;
  entry.MRnextAddr = MRnext;
  entry.MRinterface = interface;
  entry.MRdistance = distance;
}

void MulticastRoutingProtocol::AddMulticastEntry(Ipv4Address const &MRdest,
                                                 Ipv4Address const &MRnext,
                                                 Ipv4Address const &interfaceAddress,
                                                 uint32_t distance)
{
  NS_LOG_FUNCTION(this << MRdest << MRnext << interfaceAddress << distance << m_mainAddress);

  NS_ASSERT(distance > 0);
  NS_ASSERT(m_mipv4);

  MulticastRoutingTableEntry entry;
  for (uint32_t i = 0; i < m_mipv4->GetNInterfaces(); i++)
  {
    for (uint32_t j = 0; j < m_mipv4->GetNAddresses(i); j++)
    {
      if (m_mipv4->GetAddress(i, j).GetLocal() == interfaceAddress)
      {
        AddMulticastEntry(MRdest, MRnext, i, distance);
        return;
      }
    }
  }
  NS_ASSERT(false); // should not be reached
  AddMulticastEntry(MRdest, MRnext, 0, distance);
}

std::vector<MulticastRoutingTableEntry>
MulticastRoutingProtocol::GetMulticastRoutingTableEntries() const
{
  std::vector<MulticastRoutingTableEntry> retval;
  for (std::map<Ipv4Address, MulticastRoutingTableEntry>::const_iterator iter = m_mtable.begin();
       iter != m_mtable.end(); iter++)
  {
    retval.push_back(iter->second);
  }
  return retval;
}

int64_t
MulticastRoutingProtocol::AssignStreams(int64_t stream)
{
  NS_LOG_FUNCTION(this << stream);
  m_uniformRandomVariable->SetStream(stream);
  return 1;
}

bool MulticastRoutingProtocol::IsMyOwnAddress(const Ipv4Address &a) const
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
           m_socketAddresses.begin();
       j != m_socketAddresses.end(); ++j)
  {
    Ipv4InterfaceAddress iface = j->second;
    if (a == iface.GetLocal())
    {
      return true;
    }
  }
  return false;
}

void MulticastRoutingProtocol::Dump(void)
{
}

} // namespace olsr
} // namespace ns3

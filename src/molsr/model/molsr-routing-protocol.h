/*   xtt   molsr
 */

#ifndef  MOLSR_ROUTING_PROTOCOL_H
#define MOLSR_ROUTING_PROTOCOL_H

#include "molsr-header.h"
#include "molsr-state.h"
#include "molsr-repositories.h"
#include "olsr.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/event-garbage-collector.h"
#include "ns3/random-variable-stream.h"
#include "ns3/timer.h"
#include "ns3/traced-callback.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-static-routing.h"

#include <vector>
#include <map>


/********** Useful macros **********/

///获得给定时间和当前时间的延迟，在某个特定的时刻调度事件
///xtt----molsr
//发送组播声明的周期  时间固定了
//组播路由维持时间

#define DELAY(time) (((time) < (Simulator::Now())) ? Seconds(0.000001) : (time - Simulator::Now() + Seconds(0.000001)))
#include "molsr-routing-protocol.h"
#define MOLSR_PORT_NUMBER 9
/// Maximum number of messages per packet.
#define MOLSR_MAX_MSGS 64

#define MC_HOLD_TIME Time(3 * m_mclaimInterval)
//维持时间
#define SOURCE_HOLD_TIME Time(3 * m_sourceInterval)
//儿子维持时间
#define SON_HOLD_TIME Time(3 * m_confirmInterval)

#define LEAVE_HOLD_TIME Time(3 * m_confirmInterval)
/// Dup holding time.
#define MOLSR_DUP_HOLD_TIME Seconds(30)
/*******用于发送数据包的时候防止碰撞*/
/// Maximum allowed jitter.
#define MOLSR_MAXJITTER (m_confirmInterval.GetSeconds() / 20)
/// Maximum allowed sequence number.
#define MOLSR_MAX_SEQ_NUM 65535
/// Random number between [0-OLSR_MAXJITTER] used to jitter OLSR packet transmission.
#define JITTER (Seconds(m_uniformRandomVariable->GetValue(0, MOLSR_MAXJITTER)))

namespace ns3
{
namespace molsr
{

//xtt----------molsr多播路由表
struct MulticastRoutingTableEntry
{
  Ipv4Address MRdestAddr; //!< Address of the destination node.
  Ipv4Address MRnextAddr; //!< Address of the next hop.
  uint32_t MRinterface;   //!< 多播接口Interface index
  uint32_t MRdistance;    //!< 跳数Distance in hops to the destination.

  MulticastRoutingTableEntry() : // default values
                                 MRdestAddr(),
                                 MRnextAddr(),
                                 MRinterface(0), MRdistance(0)
  {
  }
};

class MulticastRoutingProtocol;

///
/// \brief OLSR routing protocol for IPv4
///
class MulticastRoutingProtocol : public Ipv4RoutingProtocol
{
public:
  /**
   * \brief Get the type ID.
   * \return The object TypeId.
   */
  static TypeId GetTypeId(void);

  MulticastRoutingProtocol();

  virtual ~MulticastRoutingProtocol();
  ////假设单接口？？？？？？？？？？
  void SetMainInterface(uint32_t interface);

  Ptr<Ipv4> m_mipv4; //组z播路由链接的ip对象
  // std::vector<Ipv4Address> SourceSet;
  // std::vector<Ipv4Address> SinkSet;

  std::set<Ipv4Address> SourceSet;
  std::set<Ipv4Address> SinkSet;
  /**
  转存邻居表之类的
   */
  void Dump(void);
  virtual int MulticastJoinGroup(Ipv4Address groupAddr, bool src, bool dst);

  virtual int MulticastLeaveGroup(Ipv4Address groupAddr);

  //xtt-----molsr 返回多播路由表项
  std::vector<MulticastRoutingTableEntry> GetMulticastRoutingTableEntries() const;
  ////信源信宿集合

  /**
   * 分配随机变量用于模型
   */
  int64_t AssignStreams(int64_t stream);

  /**
   * 回调路由表变化？？？？MOLSR
   */
  typedef void (*TableChangeTracedCallback)(uint32_t size);
  typedef void (*TreeChangeTracedCallback)(uint32_t size);
private:
  std::set<uint32_t> m_interfaceExclusions; //!< olsr排除的接口，，，单节口就设置一个判断
                                            // bool singleinterface = true;//////
  //xtt-----------molsr
  Ptr<Ipv4StaticRouting> m_multicastRoutingTableAssociation; //!< Associations from an Ipv4StaticRouting instance

public:
  std::set<uint32_t> GetInterfaceExclusions() const
  {
    return m_interfaceExclusions;
  }

  /**
     * Set the interfaces to be excluded.
     * \param exceptions Container of excluded interfaces.
     */
  void SetInterfaceExclusions(std::set<uint32_t> exceptions);

  /**
   *xtt----------molsr关联IPV4 staticrouting  table 到olsr routing protocol.
   */
  // void SetMulticastRoutingTableAssociation (Ptr<Ipv4StaticRouting> multicastRoutingTable);

  /**
   返回内部hna表
   */
  // Ptr<const Ipv4StaticRouting> GetMulticastRoutingTableAssociation () const;
  
  //OlsrState m_state; //!< Internal state with all needed data structs.
   

protected:
  virtual void DoInitialize(void);

private:
  //xtt====molsr
  std::map<Ipv4Address, MulticastRoutingTableEntry> m_mtable; //!< Data structure for the routing table.
  Ipv4Address m_mainAddress;
  //Ptr<Ipv4StaticRouting> m_hnaMulticastRoutingTable; //!< Routing table for HNA routes

  EventGarbageCollector m_events; //!< Running events.

  uint16_t m_packetSequenceNumber;  //!< Packets sequence number counter.
  uint16_t m_messageSequenceNumber; //!< Messages sequence number counter.
  uint16_t m_ansn;
  //xtt----molsr
  Time m_mclaimInterval = Seconds(30);
  Time m_sourceInterval = Seconds(15);
  Time m_confirmInterval = Seconds(10);
  // Time m_leaveInterval;

  void Clear();
  //返回路由表大小
  uint32_t GetSize() const
  {
    return m_mtable.size();
  }
  /**
删除表项,目的地址给出了
   */
  //增加组播组,用于支持组播转发  初始化组播组
 molsr::RoutingProtocol *olsr = new molsr::RoutingProtocol();
    
  //xtt--------molsr
  void McRouterTupleTimerExpire(const Ipv4Address MmAddr);
  void McTreeTupleTimerExpire(const Ipv4Address mtsourceAddr,
                              const Ipv4Address mtgroupAddr);
  void QueueMessage(const molsr::MessageHeader &message, Time delay);                   
  void SendQueuedMessages();
  void LeaveTimerExpire();
  void SendPacket(Ptr<Packet> packet, const MessageList &containedMessages);
   void SendPacketToParent (Ptr<Packet> packet, const MessageList &containedMessages,Ipv4Address address);

  void RemoveMulticastEntry(const Ipv4Address &MRdest);

  void AddMulticastEntry(const Ipv4Address &MRdest,
                         const Ipv4Address &MRnext,
                         uint32_t interface,
                         uint32_t distance);

  void AddMulticastEntry(const Ipv4Address &MRdest,
                         const Ipv4Address &MRnext,
                         const Ipv4Address &interfaceAddress,
                         uint32_t distance);
  /**
   *xtt--------molsr
   *查找有没有该地址的表项，有的话就返回到outentry返回
   */
  bool Lookup(const Ipv4Address &MRdest,
              MulticastRoutingTableEntry &outEntry) const;

  /**
  寻找能转发到该目的的条目
   */
  bool FindSendEntry(const MulticastRoutingTableEntry &entry,
                     MulticastRoutingTableEntry &outEntry) const;
  // From Ipv4MulticastRoutingProtocol  两个虚函数用于路由包和转发，output用于本地发出的数据包，input用于转发或传输接收到的包。
  //oif   输出接口设备  返回lookup里发生的

 
  virtual Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p,
                                     const Ipv4Header &header,
                                     Ptr<NetDevice> oif,
                                     Socket::SocketErrno &sockerr);

  //这个lookup在转发过程用。包被递交到ipv4静态路由。通过其中一个回调进行转发。 mcb就时用于组播转发的一个回调
  virtual bool RouteInput(Ptr<const Packet> p,
                          const Ipv4Header &header,
                          Ptr<const NetDevice> idev,
                          UnicastForwardCallback ucb,
                          MulticastForwardCallback mcb,
                          LocalDeliverCallback lcb,
                          ErrorCallback ecb);
  virtual void NotifyInterfaceUp(uint32_t interface);
  virtual void NotifyInterfaceDown(uint32_t interface);
  virtual void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address);
  virtual void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address);
  virtual void SetIpv4(Ptr<Ipv4> ipv4);
  virtual void PrintMolsrRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const;
  virtual void PrintRoutingTable (Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const ;

  void DoDispose();

  /**
   * Send an MOLSR message.
   * \param packet The packet to be sent.
   * \param containedMessages The messages contained in the packet.
   */
  //void SendPacket(Ptr<Packet> packet, const MessageList &containedMessages);

  inline uint16_t GetPacketSequenceNumber();

  inline uint16_t GetMessageSequenceNumber();

  /**
   * Receive an MOLSR message.
   * \param socket The receiving socket.
   */
  void RecvMolsr(Ptr<Socket> socket);

  //void MprComputation ();

  //xtt-------molsr
  void MulticastRoutingTableComputation();
  //xtt-------molsr 多播路由计算？
  /**
   * \brief Gets the main address associated with a given interface address.
   * \param iface_addr the interface address.
   * \return the corresponding main address.
   */

  //Ipv4Address GetMainAddress(Ipv4Address iface_addr) const;

  Ipv4Address GetGroupAddr(Ipv4Address addr) const;
 // on success,return 0,else return -1.

  void AddMulticastGroup(Ipv4Address groupAddr);

  /**
   *  \brief Tests whether or not the specified route uses a non-OLSR outgoing interface.  假设全时MOLSR外部接口
   *  \param route The route to be tested.
   *  \returns True if the outgoing interface of the specified route is a non-OLSR interface, false otherwise.
   */

  bool UsesNonMolsrOutgoingInterface(const Ipv4MulticastRoutingTableEntry &multicastroute);
  // Timer handlers
  //////xtt------molsr
  Timer m_mclaimTimer; //!< Timer for the HNA message.
  /**
   * \brieF MC_Claim的触发定时器
   */
  void MclaimTimerExpire();

  Timer m_sourceclaimTimer; //!< Timer for the HNA message.
  /**
   * \brief
   */
  void SourceTimerExpire();

  Timer m_confirmparentTimer; //!< Timer for the HNA message.
  /**
   * \brief Sends an HNA message (if the node has associated hosts/networks) and reschedules the HNA timer.
   */
  void ConfirmTimerExpire();

  Timer m_leaveTimer; //!< Timer for the HNA message.
  /**
   * \brief Sends an HNA message (if the node has associated hosts/networks) and reschedules the HNA timer.
   */
  
  /*
   * MOLSR中的复制元组,,,用于转发消息的时候
   */
  void DupTupleTimerExpire(Ipv4Address address, uint16_t sequenceNumber);

  /////////????
  /// A list of pending messages which are buffered awaiting for being sent.
  molsr::MessageList m_queuedMessages;
  Timer m_queuedMessagesTimer; //!< timer for throttling outgoing messages

  //void IncrementAnsn();

  /**
转发算法
   *
   * \param molsrMessage The %MOLSR message which must be forwarded.
   * \param duplicated NULL if the message has never been considered for forwarding, or a duplicate tuple in other case.
   * \param localIface The address of the interface where the message was received from.
   * \param senderAddress The sender IPv4 address.
   */

  ///confirm 和 leave  直接转发给父节点。
  void ForwardToParent(molsr::MessageHeader molsrMessage,
                       DuplicateTuple *duplicated,
                       const Ipv4Address &localIface,
                       const Ipv4Address &senderAddress);

  /**
   * \brief Enques an %OLSR message which will be sent with a delay of (0, delay].
   *
  让一个molsr数据包承担几个消息
   * \param message the %OLSR message which must be sent.
   * \param delay maximum delay the %OLSR message is going to be buffered.
   */
  //void QueueMessage(const molsr::MessageHeader &message, Time delay);

  /**
   * \创建molsr数据包用于发送消息
   *
   * Maximum number of messages which can be contained in an %OLSR packet is
   * dictated by OLSR_MAX_MSGS constant.
   */
  
  //xtttttttmolsr
  void SendMclaim();

  void SendSource();
  //toOrigin   routing table to originator.
  void SendConfirm();

  void SendLeave();

//  void AddIfaceAssocTuple(const IfaceAssocTuple &tuple);

 // void RemoveIfaceAssocTuple(const IfaceAssocTuple &tuple);

  ///xttttttttmolsr
  //MC路由器表，假设所有节点都具有组播能力。

  void AddMcRouterTuple(const McRouterTuple &tuple);

  void RemoveMcRouterTuple(const McRouterTuple &tuple);

  //void  UpdateMcRouterTuple (const McRouterTuple &tuple);
  //新增组播树
  void AddMcTreeTuple(const McTreeTuple &tuple);

  void RemoveMcTreeTuple(const McTreeTuple &tuple);

  void UpdateMcTreeTuple(const McTreeTuple &tuple);

  //产生组播类消息
  void ProcessMclaim(const molsr::MessageHeader &msg); //mc claim   z通过packet传输可以获取主地址

  void ProcessSource(const molsr::MessageHeader &msg,
                     const Ipv4Address &senderIfaceAddr);

  void ProcessConfirm(const molsr::MessageHeader &msg,
                      const Ipv4Address &receiverIfaceAddr,
                      const Ipv4Address &senderIfaceAddr);

  void ProcessLeave(const molsr::MessageHeader &msg,
                    const Ipv4Address &receiverIfaceAddr,
                    const Ipv4Address &senderIfaceAddr);

  /// Check that address is one of my interfaces
  bool IsMyOwnAddress(const Ipv4Address &a) const;

 // Ipv4Address m_mainAddress; //!< the node main address.

  // One socket per interface, each bound to that interface's address
  // (reason: for OLSR Link Sensing we need to know on which interface
  // HELLO messages arrive)
  std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketAddresses; //!< Container of sockets and the interfaces they are opened onto.

  /// Rx packet trace.
  TracedCallback<const PacketHeader &, const MessageList &> m_rxPacketTrace;

  /// Tx packet trace.
  TracedCallback<const PacketHeader &, const MessageList &> m_txPacketTrace;

  //xtttt---molsr
  TracedCallback<uint32_t> m_multicastRoutingTableChanged;

  TracedCallback<uint32_t> m_multicastTreeChanged;

  /// Provides uniform random variables.
  Ptr<UniformRandomVariable> m_uniformRandomVariable;
};
}
} // namespace ns3

#endif /*M OLSR_AGENT_IMPL_H */

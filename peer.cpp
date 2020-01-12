/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2011-2015  Regents of the University of California.
 *
 * This file is part of ndnSIM. See AUTHORS for complete list of ndnSIM authors and
 * contributors.
 *
 * ndnSIM is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndnSIM is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndnSIM, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include "peer.hpp"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

#include "model/ndn-l3-protocol.hpp"
#include "helper/ndn-fib-helper.hpp"
#include "ns3/random-variable-stream.h"

#include <memory>
#include <fstream>
#include <iostream>
#include <string>



#include "ns3/ptr.h"
#include "ns3/callback.h"
#include "ns3/boolean.h"
#include "ns3/integer.h"
#include "ns3/double.h"

#include "utils/ndn-ns3-packet-tag.hpp"
#include "utils/ndn-rtt-mean-deviation.hpp"

#include <ndn-cxx/lp/tags.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/ref.hpp>

NS_LOG_COMPONENT_DEFINE("ndn.Peer");

namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED(Peer);

TypeId
Peer::GetTypeId(void)
{
  static TypeId tid =
    TypeId("ns3::ndn::Peer")
      .SetGroupName("Ndn")
      .SetParent<App>()
      .AddConstructor<Peer>()
      .AddAttribute("ProducerPrefix", "Prefix, for which Peer has the data", StringValue("/"),
                    MakeNameAccessor(&Peer::m_prefix), MakeNameChecker())
	  .AddAttribute("InterestName", "Interest Name", StringValue("/"),
                    MakeNameAccessor(&Peer::m_interestName), MakeNameChecker())
      .AddAttribute(
         "Postfix",
         "Postfix that is added to the output data (e.g., for adding Peer-uniqueness)",
         StringValue("/"), MakeNameAccessor(&Peer::m_postfix), MakeNameChecker())
      .AddAttribute("PayloadSize", "Virtual payload size for Content packets", UintegerValue(1024),
                    MakeUintegerAccessor(&Peer::m_virtualPayloadSize),
                    MakeUintegerChecker<uint32_t>())
	  .AddAttribute("LifeTime", "LifeTime for interest packet", StringValue("2s"),
			        MakeTimeAccessor(&Peer::m_interestLifeTime), MakeTimeChecker())
      .AddAttribute("Freshness", "Freshness of data packets, if 0, then unlimited freshness",
                    TimeValue(Seconds(0)), MakeTimeAccessor(&Peer::m_freshness),
                    MakeTimeChecker())
      .AddAttribute(
         "Signature",
         "Fake signature, 0 valid signature (default), other values application-specific",
         UintegerValue(0), MakeUintegerAccessor(&Peer::m_signature),
         MakeUintegerChecker<uint32_t>())
      .AddAttribute("KeyLocator",
                    "Name to be used for key locator.  If root, then key locator is not used",
                    NameValue(), MakeNameAccessor(&Peer::m_keyLocator), MakeNameChecker());
  return tid;
}

Peer::Peer()
{
  NS_LOG_FUNCTION_NOARGS();
}

// inherited from Application base class.
void
Peer::StartApplication()
{
  NS_LOG_FUNCTION_NOARGS();
  App::StartApplication();


  FibHelper::AddRoute(GetNode(), m_prefix, m_face, 0);
}

void
Peer::StopApplication()
{
  NS_LOG_FUNCTION_NOARGS();

  App::StopApplication();
}

void
Peer::SendInterest()
{

	  shared_ptr<Name> interestName = make_shared<Name>(m_interestName);
	  //interestName->appendSequenceNumber(seq);
	  std::stringstream temp_comp;
	  temp_comp << m_seq;
	  interestName->append(temp_comp.str());
	  m_seq++;

	  std::cout<< " SendInterest() is working";
	  shared_ptr<Interest> interest = make_shared<Interest>();
	  interest->setNonce(m_rand->GetValue(0, std::numeric_limits<uint32_t>::max()));
	  interest->setName(*interestName);
	  //interest->setCanBePrefix(false);
	  time::milliseconds interestLifeTime(m_interestLifeTime.GetMilliSeconds());
	  interest->setInterestLifetime(interestLifeTime);

	  NS_LOG_INFO("> Interest for " << *interestName);


	  m_transmittedInterests(interest, this, m_face);
	  m_appLink->onReceiveInterest(*interest);


	  ScheduleNextPacket();
}

void
Peer::ScheduleNextPacket()
{

	  if (!m_sendEvent.IsRunning())
	      m_sendEvent = Simulator::Schedule(Seconds(1.0),&Peer::SendInterest, this);
}

void
Peer::OnInterest(shared_ptr<const Interest> interest)
{

  App::OnInterest(interest); // tracing inside

  NS_LOG_FUNCTION(this << interest);

  if (!m_active)
    return;

  std::cout<< " OnInterest() is working\n";
  Name dataName(interest->getName());
  // dataName.append(m_postfix);
  // dataName.appendVersion();

  auto data = make_shared<Data>();
  data->setName(dataName);
  data->setFreshnessPeriod(::ndn::time::milliseconds(m_freshness.GetMilliSeconds()));

  data->setContent(make_shared< ::ndn::Buffer>(m_virtualPayloadSize));

  Signature signature;
  SignatureInfo signatureInfo(static_cast< ::ndn::tlv::SignatureTypeValue>(255));

  if (m_keyLocator.size() > 0) {
    signatureInfo.setKeyLocator(m_keyLocator);
  }

  signature.setInfo(signatureInfo);
  signature.setValue(::ndn::makeNonNegativeIntegerBlock(::ndn::tlv::SignatureValue, m_signature));

  data->setSignature(signature);

  NS_LOG_INFO("node(" << GetNode()->GetId() << ") responding with Data: " << data->getName());

  // to create real wire encoding
  data->wireEncode();

  m_transmittedDatas(data, this, m_face);
  m_appLink->onReceiveData(*data);
}



void
Peer::OnData(shared_ptr<const Data> data)
{
  if (!m_active)
    return;

  App::OnData(data); // tracing inside

  std::cout<< " OnData() is working";
  NS_LOG_FUNCTION(this << data);

  // NS_LOG_INFO ("Received content object: " << boost::cref(*data));

  // This could be a problem......
  uint32_t seq = data->getName().at(-1).toSequenceNumber();
  NS_LOG_INFO("< DATA for " << data->getName());

  int hopCount = 0;
  auto hopCountTag = data->getTag<lp::HopCountTag>();
  if (hopCountTag != nullptr) { // e.g., packet came from local node's cache
    hopCount = *hopCountTag;
  }
  NS_LOG_DEBUG("Hop count: " << hopCount);


  /*
  SeqTimeoutsContainer::iterator entry = m_seqLastDelay.find(seq);
  if (entry != m_seqLastDelay.end()) {
    m_lastRetransmittedInterestDataDelay(this, seq, Simulator::Now() - entry->time, hopCount);
  }

  entry = m_seqFullDelay.find(seq);
  if (entry != m_seqFullDelay.end()) {
    m_firstInterestDataDelay(this, seq, Simulator::Now() - entry->time, m_seqRetxCounts[seq], hopCount);
  }

  m_seqRetxCounts.erase(seq);
  m_seqFullDelay.erase(seq);
  m_seqLastDelay.erase(seq);

  m_seqTimeouts.erase(seq);
  m_retxSeqs.erase(seq);

  m_rtt->AckSeq(SequenceNumber32(seq));

  */
}

} // namespace ndn
} // namespace ns3

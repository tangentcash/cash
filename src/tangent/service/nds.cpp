#include "nds.h"
#include "../storage/mempoolstate.h"

namespace Tangent
{
	namespace NDS
	{
		ServerNode::ServerNode() noexcept : ControlSys("nds-node"), Node(new HTTP::Server())
		{
		}
		ServerNode::~ServerNode() noexcept
		{
		}
		void ServerNode::Startup()
		{
			if (!Protocol::Now().User.NDS.Server)
				return;

			HTTP::MapRouter* Router = new HTTP::MapRouter();
			Router->Listen(Protocol::Now().User.NDS.Address, ToString(Protocol::Now().User.NDS.Port)).Expect("listener binding error");
			Router->Get("/", std::bind(&ServerNode::Dispatch, this, std::placeholders::_1));
			Router->Base->Callbacks.Headers = std::bind(&ServerNode::Headers, this, std::placeholders::_1, std::placeholders::_2);
			Router->Base->Callbacks.Options = std::bind(&ServerNode::Options, this, std::placeholders::_1);
			Router->TemporaryDirectory.clear();
			Node->Configure(Router).Expect("configuration error");
			Node->Listen().Expect("listen queue error");

			if (Protocol::Now().User.NDS.Logging)
				VI_INFO("[nds] nds node listen (location: %s:%i)", Protocol::Now().User.NDS.Address.c_str(), (int)Protocol::Now().User.NDS.Port);
		}
		void ServerNode::Shutdown()
		{
			if (!IsActive())
				return;

			if (Protocol::Now().User.NDS.Logging)
				VI_INFO("[nds] nds node shutdown requested");

			Node->Unlisten(false);
		}
		bool ServerNode::IsActive()
		{
			return Node->GetState() == ServerState::Working;
		}
		bool ServerNode::Headers(HTTP::Connection* Client, String& Content)
		{
			auto Headers = Client->Request.ComposeHeader("access-control-request-headers");
			if (Headers.empty())
				Headers = "Authorization";

			auto* Origin = Client->Request.GetHeaderBlob("origin");
			if (Origin != nullptr)
				Content.append("Access-Control-Allow-Origin: ").append(*Origin).append("\r\n");

			Content.append("Access-Control-Allow-Headers: *, ");
			Content.append(Headers);
			Content.append("\r\n");
			Content.append("Access-Control-Allow-Methods: GET\r\n");
			Content.append("Access-Control-Allow-Credentials: true\r\n");
			Content.append("Access-Control-Max-Age: 86400\r\n");
			return true;
		}
		bool ServerNode::Options(HTTP::Connection* Client)
		{
			char Date[64];
			String* Content = HTTP::HrmCache::Get()->Pop();
			Content->append(Client->Request.Version);
			Content->append(" 204 No Content\r\nDate: ");
			Content->append(DateTime::SerializeGlobal(Date, sizeof(Date), std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::milliseconds(Client->Info.Start)), DateTime::FormatWebTime())).append("\r\n", 2);
			Content->append("Allow: GET\r\n");

			HTTP::Utils::UpdateKeepAliveHeaders(Client, *Content);
			if (Client->Route && Client->Route->Callbacks.Headers)
				Client->Route->Callbacks.Headers(Client, *Content);

			Content->append("\r\n", 2);
			return !!Client->Stream->WriteQueued((uint8_t*)Content->c_str(), Content->size(), [Client, Content](SocketPoll Event)
			{
				HTTP::HrmCache::Get()->Push(Content);
				if (Packet::IsDone(Event))
					Client->Next(204);
				else if (Packet::IsError(Event))
					Client->Abort();
			}, false);
		}
		bool ServerNode::Dispatch(HTTP::Connection* Base)
		{
			HTTP::Query Query;
			Query.Decode("application/x-www-form-urlencoded", Base->Request.Query);

			auto* ConsensusArgument = Query.Get("consensus");
			auto* DiscoveryArgument = Query.Get("discovery");
			auto* InterfaceArgument = Query.Get("interface");
			auto* ProposerArgument = Query.Get("proposer");
			auto* StreamingArgument = Query.Get("streaming");
			auto* PublicArgument = Query.Get("public");
			auto* OffsetArgument = Query.Get("offset");
			auto* CountArgument = Query.Get("count");
			uint64_t Count = CountArgument && CountArgument->Value.Is(VarType::Integer) ? CountArgument->Value.GetInteger() : Protocol::Now().User.NDS.CursorSize;
			if (!Count || Count > Protocol::Now().User.NDS.CursorSize)
			{
				if (Protocol::Now().User.NDS.Logging)
					VI_WARN("[nds] peer %s discovery failed: bad arguments (time: %" PRId64 " ms, args: %s)", Base->GetPeerIpAddress().Or("[bad_address]").c_str(), DateTime().Milliseconds() - Base->Info.Start, Base->Request.Query.c_str());

				return Base->Abort(400, "Bad page size. Count must not exceed %" PRIu64 " elements.", Protocol::Now().User.NDS.CursorSize);
			}

			uint32_t Services = 0;
			if (ConsensusArgument != nullptr && ConsensusArgument->Value.GetBoolean())
				Services |= (uint32_t)Storages::NodeServices::Consensus;
			if (DiscoveryArgument != nullptr && DiscoveryArgument->Value.GetBoolean())
				Services |= (uint32_t)Storages::NodeServices::Discovery;
			if (InterfaceArgument != nullptr && InterfaceArgument->Value.GetBoolean())
				Services |= (uint32_t)Storages::NodeServices::Interface;
			if (ProposerArgument != nullptr && ProposerArgument->Value.GetBoolean())
				Services |= (uint32_t)Storages::NodeServices::Proposer;
			if (PublicArgument != nullptr && PublicArgument->Value.GetBoolean())
				Services |= (uint32_t)Storages::NodeServices::Public;
			if (StreamingArgument != nullptr && StreamingArgument->Value.GetBoolean())
				Services |= (uint32_t)Storages::NodeServices::Streaming;

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Seeds = Mempool.GetRandomizedValidatorAddresses(Count, Services);
			if (!Seeds || Seeds->empty())
			{
				if (Protocol::Now().User.NDS.Logging)
					VI_INFO("[nds] peer %s discovery: no nodes returned (time: %" PRId64 " ms, args: %s)", Base->GetPeerIpAddress().Or("[bad_address]").c_str(), DateTime().Milliseconds() - Base->Info.Start, Base->Request.Query.c_str());

				return Base->Abort(404, "No nodes found.");
			}

			if (Protocol::Now().User.NDS.Logging)
				VI_INFO("[nds] peer %s discovery: %i nodes returned (time: %" PRId64 " ms, args: %s)", Base->GetPeerIpAddress().Or("[bad_address]").c_str(), (int)Seeds->size(), DateTime().Milliseconds() - Base->Info.Start, Base->Request.Query.c_str());

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Seed : *Seeds)
				Data->Push(Var::String(Algorithm::Endpoint::ToURI(Seed)));

			Base->Response.SetHeader("Content-Type", "application/json");
			Base->Response.Content.Assign(Schema::ToJSON(*Data));
			return Base->Next(200);
		}
		ServiceControl::ServiceNode ServerNode::GetEntrypoint()
		{
			if (!Protocol::Now().User.NDS.Server)
				return ServiceControl::ServiceNode();

			ServiceControl::ServiceNode Entrypoint;
			Entrypoint.Startup = std::bind(&ServerNode::Startup, this);
			Entrypoint.Shutdown = std::bind(&ServerNode::Shutdown, this);
			return Entrypoint;
		}
	}
}
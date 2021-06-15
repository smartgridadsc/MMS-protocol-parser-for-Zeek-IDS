// Generated by binpac_quickstart

#ifndef ANALYZER_PROTOCOL_MMS_MMS_H
#define ANALYZER_PROTOCOL_MMS_MMS_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "mms_pac.h"


namespace analyzer { namespace MMS {

class MMS_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	MMS_Analyzer(Connection* conn);
	virtual ~MMS_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new MMS_Analyzer(conn); }

protected:
	binpac::MMS::MMS_Conn* interp;
	
	bool had_gap;
	
};

} } // namespace analyzer::* 

#endif
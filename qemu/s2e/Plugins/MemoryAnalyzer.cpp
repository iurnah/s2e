/*
 * MemoryAnalyzer.cpp
 *
 *  Created on: April 13, 2014
 *      Author: Rui Han
 */

#include <iomanip>
#include <inttypes.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include "MemoryAnalyzer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MemoryAnalyzer, "Memory Analyzer Plugin", "MemoryAnalyzer", "ExecutionTracer");

MemoryAnalyzer::MemoryAnalyzer(S2E* s2e): Plugin(s2e) {}

/*********************************************************************************
 *	initialize the MemoryAnalyzer
 *	(1) connect to the dependency plugins
 *	(2) reading the configured values
 *********************************************************************************/
void MemoryAnalyzer::initialize(){
	m_tracer = static_cast<ExecutionTracer*>(s2e()->getPlugin("ExecutionTracer"));
	m_executionDetector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));

	m_monitorModules = s2e()->getConfig()->getBool(getConfigKey() + ".monitorModules");
	if (m_monitorModules && !m_execDetector) {
		s2e()->getWarningsStream() << "MemoryAnalyzer: The monitorModule option requires ModuleExecutionDetector\n";
		exit(-1);
	}

	m_memoryMonitor = s2e()->getConfig()->getBool(getConfigKey() + ".memoryMonitor");
	m_stackMonitor = s2e()->getConfig()->getBool(getConfigKey() + ".stackMonitor");
	m_heapMonitor = s2e()-getConfig()->getBool(getConfigKey() + ".heapMonitor");

	s2e()->getDebugStream() << "MonitorMemory: " << m_monitorMemory << "StackMonitor" 
			<< m_stackMonitor << "HeapMonitor" << m_heapMonitor << std::endl;

	enableTracing();

	/* Initialize the shadow memory */
	init_shadow_memory();	
}

/*********************************************************************************
 *	
 *********************************************************************************/
void MemoryAnalyzer::enableTracing(){
	if(m_monitorMemory){
		s2e()->getMessagesStream() << "MemoryAnalyzer Plugin: Enable memory tracing" << std::endl;
		m_DataMemoryMonitor.disconnect();
		
		if(m_monitorModules){
			//XXX: is this saying that we are going to change to another module
			m_executionDetector->onModuleTransition.connect(	//handle the module detection
					sigc::mem_fun(*this, &MemoryAnalyzer::onModuleTransition));
		} else {
			m_DatamemoryMonitor = s2e()->getCorePlugin()->onDataMemoryAccess.connect(
					sigc::mem_fun(*this, &MemoryAnalyzer::onDataMemoryAccess));
		}
	}
}

/*********************************************************************************
 *	
 *********************************************************************************/
void MemoryAnalyzer::onModuleTransition(S2EExecutionState *state,
										const ModuleDescriptor *prevModule,
										const ModuleDescriptor *nextModule)
{
	ModuleDescriptor *currentDescriptor = m_executionDetector->getCurrentDescriptor(state);

	if(currentDescriptor->name == nextModule->name && !m_DataMomoryMonitor.connect()){
		m_DataMemoryMonitor = s2e()->getCorePlugin()->onDataMemoryAccess.connect(
				sigc::mem_fun(*this, &MemoryAnalyzer::onDataMemoryAccess));		
	} else {
		m_DataMemoryMonitor.disconnect();
	}
}

/*********************************************************************************
 *	
 *********************************************************************************/
void MemoryAnalyzer::onDataMemoryAccess(S2EExecutionState *state,
								klee::ref<klee::Expr> address,
								klee::ref<klee::Expr> hostAddress,
								klee::ref<klee::Expr> value,
								bool isWrite, bool isIO)
{	//XXX:there is a hack. use with caution
	traceDataMemoryAccess(state, address, hostAddress, value, isWrite, isIO);
}

/*********************************************************************************
 *	
 *********************************************************************************/
void MemoryAnalyzer::traceDataMemoryAccess(S2EExecutionState *state,
								klee::ref<klee::Expr> &address,
								klee::ref<klee::Expr> &hostAddress,
								klee::ref<klee::Expr> &value
								bool isWrite, bool isIO)
{
	bool isAddrCste = isa<klee::ConstantExpr>(address);
	bool isValCste = isa<klee::ConstantExpr>(value);
	bool isHostAddrCste = isa<klee::ConstantExpr>(hostAddress);

	ExecutionTraceMemory e;
	e.flags = 0;
	e.pc = state->getPc();

	uint64_t concreteAddress = 0xdeadbeef;
	uint64_t concreteValue = 0xdeadbeef;

/*
	if(ConcolicMode) {
		klee::ref<klee::ConstantExpr> 
				ce = dyn_cast<klee::ConstantExpr>(state->concolics.evaluate(address)); 
		concreteAddress = ce->getZExtValue();

		ce = dyn_cast<klee::ConstantExpr>(state->concolics.evaluate(value));
		concreteValue = ce->getZExtValue();
	}
*/

	e.address = isAddrCste ? cast<klee::ConstantExpr>(address)->getZExtValue(64) : concreteAddress;
	e.value = isValCste ? cast<klee::ConstantExpr>(value)->getZExtValue(64) : concreteValue;
	e.size = klee::Expr::getMinBytesForWidth(value->getWidth());
	e.flags = isWrite*EXECTRACE_MEM_WRITE | isIO*EXECTRACE_MEM_IO;
	e.hostAddress = isHostAddrCste ? case<klee::ConstantExpr>(hostAddress)->getZExtValue(64) : 0xDEADBEEF;

	if(!isAddrCste){
		e.flags |= EXECTRACE_MEM_SYMBADDR;
	}

    if(!isValCste){
		e.flags |= EXECTRACE_MEM_SYMBVAL;
	}
	
    if(!isHostAddrCste){
		e.flags |= EXECTRACE_MEM_SYMBHOSTADDR;
	}
	
	unsigned strucSize = sizeof(e);
	if(!(e.flags & EXECTRACE_MEM_HASHOSTADDR) && !(e.flags & EXECTRACE_MEM_OBJECTSTATE)){
		strucSize -= (sizeof(e.hostAddress) + sizeof(e.concreteBuffer));	
	}

	m_tracer->writeData(state, &e, sizeof(e), TRACE_MEMORY);
}

/*********************************************************************************
 *	
 *********************************************************************************/
void onMemoryWrite(){

}

/*********************************************************************************
 *	obtained the data type from system call parameters	
 *********************************************************************************/
void onSyscallTypeSink(){

}

/*********************************************************************************
 *	obtained the data type from system call parameters	
 *********************************************************************************/
void onLibcallTypeSink(){

}

/*********************************************************************************
 *	obtained the data type from system call parameters	
 *********************************************************************************/
void onInstructionTypeSink(){

}

} //namespace plugins 
} //namespace s2e

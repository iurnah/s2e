/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include <iomanip>
#include <inttypes.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include "MemoryAnalyzer.h"

#include <llvm/Support/CommandLine.h>

extern llvm::cl::opt<bool> ConcolicMode;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(MemoryAnalyzer, "Memory Analyzer plugin", "MemoryAnalyzer", "ExecutionTracer");

MemoryAnalyzer::MemoryAnalyzer(S2E* s2e)
        : Plugin(s2e)
{

}

void MemoryAnalyzer::initialize()
{

    m_tracer = static_cast<ExecutionTracer*>(s2e()->getPlugin("ExecutionTracer"));
    m_execDetector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));

    //Retrict monitoring to configured modules only
    m_monitorModules = s2e()->getConfig()->getBool(getConfigKey() + ".monitorModules");
    if (m_monitorModules && !m_execDetector) {
        s2e()->getWarningsStream() << "MemoryAnalyzer: The monitorModules option requires ModuleExecutionDetector\n";
        exit(-1);
    }

    //Catch all accesses to the stack
    m_monitorStack = s2e()->getConfig()->getBool(getConfigKey() + ".monitorStack");

    //Catch accesses that are above the specified address
    m_catchAbove = s2e()->getConfig()->getInt(getConfigKey() + ".catchAccessesAbove");
    m_catchBelow = s2e()->getConfig()->getInt(getConfigKey() + ".catchAccessesBelow");

    //Whether or not to include host addresses in the trace.
    //This is useful for debugging, bug yields larger traces
    m_traceHostAddresses = s2e()->getConfig()->getBool(getConfigKey() + ".traceHostAddresses");

    //Check that the current state is actually allowed to write to
    //the object state. Can be useful to debug the engine.
    m_debugObjectStates = s2e()->getConfig()->getBool(getConfigKey() + ".debugObjectStates");

    //Start monitoring after the specified number of seconds
    bool hasTimeTrigger = false;
    m_timeTrigger = s2e()->getConfig()->getInt(getConfigKey() + ".timeTrigger", 0, &hasTimeTrigger);
    m_elapsedTics = 0;

    bool manualMode = s2e()->getConfig()->getBool(getConfigKey() + ".manualTrigger");

    m_monitorMemory = s2e()->getConfig()->getBool(getConfigKey() + ".monitorMemory");
    m_monitorPageFaults = s2e()->getConfig()->getBool(getConfigKey() + ".monitorPageFaults");
    m_monitorTlbMisses  = s2e()->getConfig()->getBool(getConfigKey() + ".monitorTlbMisses");

    s2e()->getDebugStream() << "MonitorMemory: " << m_monitorMemory << 
    " PageFaults: " << m_monitorPageFaults << " TlbMisses: " << m_monitorTlbMisses << '\n';

    if (hasTimeTrigger) {
        m_timerConnection = s2e()->getCorePlugin()->onTimer.connect(
                sigc::mem_fun(*this, &MemoryAnalyzer::onTimer));
    } else if (manualMode) {
        s2e()->getCorePlugin()->onCustomInstruction.connect(
                sigc::mem_fun(*this, &MemoryAnalyzer::onCustomInstruction));
    } else {
        enableTracing();
    }
}

void MemoryAnalyzer::traceDataMemoryAccess(S2EExecutionState *state,
                               klee::ref<klee::Expr> &address,
                               klee::ref<klee::Expr> &hostAddress,
                               klee::ref<klee::Expr> &value,
                               bool isWrite, bool isIO)
{
    if (m_catchAbove || m_catchBelow) {
        if (m_catchAbove && (m_catchAbove >= state->getPc())) {
            return;
        }
        if (m_catchBelow && (m_catchBelow < state->getPc())) {
            return;
        }
    }

    bool isAddrCste = isa<klee::ConstantExpr>(address);
    bool isValCste = isa<klee::ConstantExpr>(value);
    bool isHostAddrCste = isa<klee::ConstantExpr>(hostAddress);

    //Output to the trace entry here
    ExecutionTraceMemory e;
    e.flags = 0;
    e.pc = state->getPc();

    uint64_t concreteAddress = 0xdeadbeef;
    uint64_t concreteValue = 0xdeadbeef;
    if (ConcolicMode) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(state->concolics.evaluate(address));
        concreteAddress = ce->getZExtValue();

        ce = dyn_cast<klee::ConstantExpr>(state->concolics.evaluate(value));
        concreteValue = ce->getZExtValue();
    }

    e.address = isAddrCste ? cast<klee::ConstantExpr>(address)->getZExtValue(64) : concreteAddress;
    e.value = isValCste ? cast<klee::ConstantExpr>(value)->getZExtValue(64) : concreteValue;
    e.size = klee::Expr::getMinBytesForWidth(value->getWidth());
    e.flags = isWrite*EXECTRACE_MEM_WRITE |
                 isIO*EXECTRACE_MEM_IO;

    e.hostAddress = isHostAddrCste ? cast<klee::ConstantExpr>(hostAddress)->getZExtValue(64) : 0xDEADBEEF;

    if (m_traceHostAddresses) {
        e.flags |= EXECTRACE_MEM_HASHOSTADDR;
        e.flags |= EXECTRACE_MEM_OBJECTSTATE;

        klee::ObjectPair op = state->addressSpace.findObject(e.hostAddress & S2E_RAM_OBJECT_MASK);
        e.concreteBuffer = 0;
        if (op.first && op.second) {
            e.concreteBuffer = (uint64_t) op.second->getConcreteStore();
            if (isWrite && m_debugObjectStates) {
                assert(state->addressSpace.isOwnedByUs(op.second));
            }
        }
    }

    if (!isAddrCste) {
       e.flags |= EXECTRACE_MEM_SYMBADDR;
    }

    if (!isValCste) {
       e.flags |= EXECTRACE_MEM_SYMBVAL;
    }

    if (!isHostAddrCste) {
       e.flags |= EXECTRACE_MEM_SYMBHOSTADDR;
    }

    unsigned strucSize = sizeof(e);
    if (!(e.flags & EXECTRACE_MEM_HASHOSTADDR) && !(e.flags & EXECTRACE_MEM_OBJECTSTATE)) {
        strucSize -= (sizeof(e.hostAddress) + sizeof(e.concreteBuffer));
    }
/*	
	s2e()->getWarningsStream() << "S=" << state->getID() << " P=0x" << hexval(state->getPid())
			<< " PC=0x" << hexval(state->getPc()) << " ---R4" << "[0x" << hexval(e.address) << "]=0x"
			<< hexval(e.value) << "HostAddress:" << hexval(e.hostAddress) << '\n';
*/
    m_tracer->writeData(state, &e, sizeof(e), TRACE_MEMORY);
}

void MemoryAnalyzer::onDataMemoryAccess(S2EExecutionState *state,
                               klee::ref<klee::Expr> address,
                               klee::ref<klee::Expr> hostAddress,
                               klee::ref<klee::Expr> value,
                               bool isWrite, bool isIO)
{
    //XXX: This is a hack.
    //Sometimes the onModuleTransition is not fired properly...
    if (m_execDetector && m_monitorModules && !m_execDetector->getCurrentDescriptor(state)) {
        m_memoryMonitor.disconnect();
        return;
    }
		
	
/*
	s2e()->getWarningsStream() << "S=" << std::dec << hdr.stateId << " P=0x" << std::hex << hdr.pid 
			<< " PC=0x" << std::hex << te->pc << " " << type << (int)te->size 
			<< "[0x" << std::hex << te->address << "]=0x" << std::setw(10) << std::setfill('0') << te->value;
*/
    traceDataMemoryAccess(state, address, hostAddress, value, isWrite, isIO);
}

void MemoryAnalyzer::onModuleTransition(S2EExecutionState *state,
                                       const ModuleDescriptor *prevModule,
                                       const ModuleDescriptor *nextModule)
{
    if (nextModule && !m_memoryMonitor.connected()) {
        m_memoryMonitor =
            s2e()->getCorePlugin()->onDataMemoryAccess.connect(
                sigc::mem_fun(*this, &MemoryAnalyzer::onDataMemoryAccess)
            );
    } else {
        m_memoryMonitor.disconnect();
    }
}


void MemoryAnalyzer::onTlbMiss(S2EExecutionState *state, uint64_t addr, bool is_write)
{
    ExecutionTraceTlbMiss e;
    e.pc = state->getPc();
    e.address = addr;
    e.isWrite = is_write;

    m_tracer->writeData(state, &e, sizeof(e), TRACE_TLBMISS);
}

void MemoryAnalyzer::onPageFault(S2EExecutionState *state, uint64_t addr, bool is_write)
{
    ExecutionTracePageFault e;
    e.pc = state->getPc();
    e.address = addr;
    e.isWrite = is_write;

    m_tracer->writeData(state, &e, sizeof(e), TRACE_PAGEFAULT);
}

void MemoryAnalyzer::enableTracing()
{
    if (m_monitorMemory) {
        s2e()->getMessagesStream() << "MemoryAnalyzer Plugin: Enabling memory tracing" << '\n';
        m_memoryMonitor.disconnect();

        if (m_monitorModules) {
            m_execDetector->onModuleTransition.connect(
                    sigc::mem_fun(*this,
                            &MemoryAnalyzer::onModuleTransition)
                    );
        } else {
            m_memoryMonitor = s2e()->getCorePlugin()->onDataMemoryAccess.connect(
                    sigc::mem_fun(*this, &MemoryAnalyzer::onDataMemoryAccess));
        }
    }

    if (m_monitorPageFaults) {
        s2e()->getMessagesStream() << "MemoryAnalyzer Plugin: Enabling page fault tracing" << '\n';
        m_pageFaultsMonitor.disconnect();
        m_pageFaultsMonitor = s2e()->getCorePlugin()->onPageFault.connect(
                sigc::mem_fun(*this, &MemoryAnalyzer::onPageFault));
    }

    if (m_monitorTlbMisses) {
        s2e()->getMessagesStream() << "MemoryAnalyzer Plugin: Enabling TLB miss tracing" << '\n';
        m_tlbMissesMonitor.disconnect();
        m_tlbMissesMonitor = s2e()->getCorePlugin()->onTlbMiss.connect(
                sigc::mem_fun(*this, &MemoryAnalyzer::onTlbMiss));
    }
}

void MemoryAnalyzer::disableTracing()
{
    m_memoryMonitor.disconnect();
    m_pageFaultsMonitor.disconnect();
    m_tlbMissesMonitor.disconnect();
}

void MemoryAnalyzer::onTimer()
{
    if (m_elapsedTics++ < m_timeTrigger) {
        return;
    }

    enableTracing();

    m_timerConnection.disconnect();
}

void MemoryAnalyzer::onCustomInstruction(S2EExecutionState* state, uint64_t opcode)
{
    if (!OPCODE_CHECK(opcode, MEMORY_TRACER_OPCODE)) {
        return;
    }

    uint64_t subfunction = OPCODE_GETSUBFUNCTION(opcode);

    MemoryAnalyzerOpcodes opc = (MemoryAnalyzerOpcodes)subfunction;
    switch(opc) {
    case Enable:
        enableTracing();
        break;

    case Disable:
        disableTracing();
        break;

    default:
        s2e()->getWarningsStream() << "MemoryAnalyzer: unsupported opcode " << hexval(opc) << '\n';
        break;
    }

}

}
}

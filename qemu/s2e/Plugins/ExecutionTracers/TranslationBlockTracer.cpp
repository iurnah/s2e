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

extern "C" {
#include "config.h"
#include "cpu.h"
//#include "exec-all.h"
#include "qemu-common.h"
extern CPUArchState *env;
}

#include "TranslationBlockTracer.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TranslationBlockTracer, "Tracer for executed translation blocks", "TranslationBlockTracer", 
					"ExecutionTracer",
					"ModuleExecutionDetector");

struct X86State {
   uint32_t eax;
   uint32_t ecx;
   uint32_t edx;
   uint32_t ebx;
   uint32_t esi;
   uint32_t edi;
   uint32_t ebp;
   uint32_t esp;
   uint32_t eip;
   uint32_t cr2;
}s;

const char *RegSymbol[] = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };

/* shadow memory parameters */
#define PAGE_SIZE 65536 //2^16
#define PAGE_NUM 262144 //2^18
#define SHADOW_BYTES 4
#define TAG_INVALID 0xDEADBEEF
#define SEG_MASK 0x3fffffff//0xC0000000
#define PAGE_NUM_BITS 16
#define OFF_SET_BITS 14
#define ADDR_MIN 4294967290//3147483640//16376 //for test
#define ADDR_MAX 4294967295//3147483648//16385 //for test
/*
 * virtual address used to query shadow memory 
 *            32bit virtual address
         --------------------------------
         SG| pg_num=16bit |off_set=14bit|
         --------------------------------
 */
typedef struct {
	uint32_t page[PAGE_SIZE/SHADOW_BYTES];
} shadowPage;

static shadowPage s_page;
static shadowPage *shadowMemory[4][PAGE_NUM/SHADOW_BYTES];

void shadowMemoryInit(void)
{
	int32_t i, j;
	//int size;	

	for(i = 0; i < PAGE_SIZE/SHADOW_BYTES; i++)
		s_page.page[i] = TAG_INVALID;	

	for(j = 0; j < 4; j++)
		for(i = 0; i < PAGE_NUM/SHADOW_BYTES; i++){
			shadowMemory[j][i] = &s_page;
		}
}

/** get the 32 bit shadow memory contents for the addresss in the shadow memory */
static uint32_t get_mem_ins_addr(uint32_t addr) 
{
	shadowPage *sm;
	sm = shadowMemory[addr >> (PAGE_NUM_BITS + OFF_SET_BITS)][(addr & SEG_MASK) >> OFF_SET_BITS ];

	uint32_t sm_off = addr & 0x3FFF;
	//cout << sm_off << endl;
	return (sm->page)[sm_off];
}

/** set the 32 bit shadow memory contents for the addresss in the shadow memory */
static void set_mem_ins_addr(uint32_t addr, uint32_t bytes)
{
	shadowPage *sm;
	sm = shadowMemory[addr >> (PAGE_NUM_BITS + OFF_SET_BITS)][(addr & SEG_MASK) >> OFF_SET_BITS ];
	uint32_t sm_off = addr & 0x3FFF;
	//cout << sm_off << endl;
	(sm->page)[sm_off] = bytes;
}

void TranslationBlockTracer::initialize()
{
    m_tracer = (ExecutionTracer *)s2e()->getPlugin("ExecutionTracer");
    m_detector = (ModuleExecutionDetector*)s2e()->getPlugin("ModuleExecutionDetector");

    bool ok = false;
    //Specify whether or not to enable cutom instructions for enabling/disabling tracing
    bool manualTrigger = s2e()->getConfig()->getBool(getConfigKey() + ".manualTrigger", false, &ok);

    //Whether or not to flush the translation block cache when enabling/disabling tracing.
    //This can be useful when tracing is enabled in the middle of a run where most of the blocks
    //are already translated without the tracing instrumentation enabled.
    //The default behavior is ON, because otherwise it may produce confising results.
    m_flushTbOnChange = s2e()->getConfig()->getBool(getConfigKey() + ".flushTbCache", true);

    if (manualTrigger) {
        s2e()->getCorePlugin()->onCustomInstruction.connect(
                sigc::mem_fun(*this, &TranslationBlockTracer::onCustomInstruction));
    }else {
        enableTracing();
    }
}

void TranslationBlockTracer::enableTracing()
{
    if (m_flushTbOnChange) {
        tb_flush(env);
    }

    m_tbStartConnection = m_detector->onModuleTranslateBlockStart.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onModuleTranslateBlockStart));

    m_tbEndConnection = m_detector->onModuleTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &TranslationBlockTracer::onModuleTranslateBlockEnd));
#if 0
	m_onLoadStroeConnection = s2e()->getCorePlugin()->onLoadStoreInstruction.connect(
			sigc::mem_fun(*this, &TranslationBlockTracer::onLoadStoreInstruction));
#endif
}

void TranslationBlockTracer::disableTracing()
{
    if (m_flushTbOnChange) {
        tb_flush(env);
    }

    m_tbStartConnection.disconnect();
    m_tbEndConnection.disconnect();
	//m_onLoadStoreConnection.disconnect();
}
#if 0
/* member function to receive the source and destination operator */
void TranslationBlockTracer::onGen_LoadStore(ExecutionSignal *signal,
				S2EExecutionState *state, 
				TranslationBlock *tb,
				uint64_t pc, int dest, int src){

	s2e()->getDebugStream() << "WE HAVE THE onGen_LoadStore(): PC = " << pc << " dest = " << dest << " src = " << src << '\n';

}
#endif

void TranslationBlockTracer::onModuleTranslateBlockStart(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t pc)
{
    signal->connect(
        sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockStart)
    );
}

void TranslationBlockTracer::onModuleTranslateBlockEnd(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t endPc,
        bool staticTarget,
        uint64_t targetPc)
{
    signal->connect(
        sigc::mem_fun(*this, &TranslationBlockTracer::onExecuteBlockEnd)
    );
}

//The real tracing is done here
//-----------------------------
void TranslationBlockTracer::trace(S2EExecutionState *state, uint64_t pc, ExecTraceEntryType type)
{
    ExecutionTraceTb tb;

    if (type == TRACE_TB_START) {
        if (pc != state->getTb()->pc) {
            s2e()->getWarningsStream() << "BUG! pc=" << hexval(pc)
                                       << " tbpc=" << hexval(state->getTb()->pc) << '\n';
            exit(-1);
        }
    }

    tb.pc = pc;
    tb.targetPc = state->getPc();
    tb.tbType = state->getTb()->s2e_tb_type;
    tb.symbMask = 0;
    tb.size = state->getTb()->size;
    memset(tb.registers, 0x55, sizeof(tb.registers));

    assert(sizeof(tb.symbMask)*8 >= sizeof(tb.registers)/sizeof(tb.registers[0]));
    for (unsigned i=0; i<sizeof(tb.registers)/sizeof(tb.registers[0]); ++i) {
        //XXX: make it portable across architectures
        unsigned size = sizeof (target_ulong) < sizeof (*tb.registers) ?
                        sizeof (target_ulong) : sizeof (*tb.registers);
        unsigned offset = CPU_REG_OFFSET(i);
        if (!state->readCpuRegisterConcrete(offset, &tb.registers[i], size)) {
            tb.registers[i]  = 0xDEADBEEF;
            tb.symbMask |= 1<<i;
        }
    }

    m_tracer->writeData(state, &tb, sizeof(tb), type);

}

#if 0
void TranslationBlockTracer::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    trace(state, pc, TRACE_TB_START);
}

void TranslationBlockTracer::onExecuteBlockEnd(S2EExecutionState *state, uint64_t pc)
{
    trace(state, pc, TRACE_TB_END);
}
#endif

void TranslationBlockTracer::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    trace(state, pc, TRACE_TB_START);
	/* get the register value at the very begining of the each translation block
	 * execution or get the register value at each onPropagation.*/

	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EAX]), &(s.eax), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(s.esp), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );

	s2e()->getDebugStream(state) << "[per block]PC = " << hexval(pc) 
			<< " EAX = " << hexval(s.eax) << " ECX = " << hexval(s.ecx) 
			<< " EDX = " << hexval(s.edx) << " EBX = " << hexval(s.ebx) 
			<< " ESP = " << hexval(s.esp) << " EBP = " << hexval(s.ebp) 
			<< " ESI = " << hexval(s.esi) << " EDI = " << hexval(s.edi) << '\n';

	m_onLoadStoreConnection = s2e()->getCorePlugin()->onLoadStoreInstruction.connect(sigc::mem_fun(*this, &TranslationBlockTracer::onLoadStoreInstruction));

}

void TranslationBlockTracer::onLoadStoreInstruction(ExecutionSignal *signal,
				S2EExecutionState *state, 
				TranslationBlock *tb,
				uint64_t pc, int dest, int src){
	/* We can also read the register value at this point, this is good for
	 * analysis and better then reading at the very begining of each execution
	 * block */
	
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EAX]), &(s.eax), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBX]), &(s.ebx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ECX]), &(s.ecx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDX]), &(s.edx), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESI]), &(s.esi), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EDI]), &(s.edi), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_EBP]), &(s.ebp), sizeof (uint32_t) );
	state->readCpuRegisterConcrete (CPU_OFFSET (regs[R_ESP]), &(s.esp), sizeof (uint32_t) );

	s2e()->getDebugStream(state) << "[per insn]PC = " << hexval(pc) << "EAX = " << hexval(s.eax) << " EBX = " << hexval(s.ebx) << " ECX = " << hexval(s.ecx) << " EDX = " << hexval(s.edx) << " ESI = " << hexval(s.esi) << " EDI = " << hexval(s.edi) << " EBP = " << hexval(s.ebp) << " ESP = " << hexval(s.esp) << '\n';

	s2e()->getDebugStream() << "Data Propagation: " << RegSymbol[src] << " --> " << RegSymbol[dest] << '\n';
	//TODO: Insert the analysis code and the shadow memory code here	
	set_mem_ins_addr(s.esp, -1);	
	set_mem_ins_addr(s.ebp, -1);

	s2e()->getDebugStream(state) << "SHADOW MEMORY: " << get_mem_ins_addr(s.esp) << '\n';
}

void TranslationBlockTracer::onExecuteBlockEnd(S2EExecutionState *state, uint64_t pc)
{
	/* We disconnect */
	m_onLoadStoreConnection.disconnect();
	s2e()->getDebugStream(state) << "onLoadStoreInstruction disconnected!!!" << '\n';

    trace(state, pc, TRACE_TB_END);
}

void TranslationBlockTracer::onCustomInstruction(S2EExecutionState* state, uint64_t opcode)
{
    //XXX: find a better way of allocating custom opcodes
    if (((opcode>>8) & 0xFF) != TB_TRACER_OPCODE) {
        return;
    }

    //XXX: remove this mess. Should have a function for extracting
    //info from opcodes.
    opcode >>= 16;
    uint8_t op = opcode & 0xFF;
    opcode >>= 8;


    TbTracerOpcodes opc = (TbTracerOpcodes)op;
    switch(opc) {
    case Enable:
        enableTracing();
        break;

    case Disable:
        disableTracing();
        break;

    default:
        s2e()->getWarningsStream() << "MemoryTracer: unsupported opcode " << hexval(opc) << '\n';
        break;
    }

}

} // namespace plugins
} // namespace s2e

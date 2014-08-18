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

#ifndef S2E_PLUGINS_STACKMONITOR_H
#define S2E_PLUGINS_STACKMONITOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include "ModuleExecutionDetector.h"
#include "ExecutionStatisticsCollector.h"
#include "OSMonitor.h"

#if defined(TARGET_I386)
#define SP_REG R_ESP
#elif defined(TARGET_ARM)
#define SP_REG 13
#endif

namespace s2e {
namespace plugins {

struct StackFrameInfo {
    uint64_t StackBase;
    uint64_t StackSize;
    uint64_t FrameTop;
    uint64_t FrameSize;
    uint64_t FramePc;
};

typedef std::vector<uint64_t> CallStack;
typedef std::vector<CallStack> CallStacks;

class StackMonitorState;

class StackMonitor : public Plugin
{
    S2E_PLUGIN
public:
    friend class StackMonitorState;
    StackMonitor(S2E* s2e): Plugin(s2e) {}

    void initialize();

    bool getFrameInfo(S2EExecutionState *state, uint64_t sp, bool &onTheStack, StackFrameInfo &info) const;
    void dump(S2EExecutionState *state);

    bool getCallStacks(S2EExecutionState *state, CallStacks &callStacks) const;

    /**
     * Emitted when a new stack frame is setup (e.g., when execution
     * enters a module of interest.
     */
    sigc::signal<void, S2EExecutionState*> onStackCreation;

    /**
     * Emitted when there are no more stack frames anymore.
     */
    sigc::signal<void, S2EExecutionState*> onStackDeletion;

private:
    OSMonitor *m_monitor;
    ModuleExecutionDetector *m_detector;
    ExecutionStatisticsCollector *m_statsCollector;
    bool m_debugMessages;

    sigc::connection m_onTranslateRegisterAccessConnection;

    void onThreadCreate(S2EExecutionState *state, const ThreadDescriptor &thread);
    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);

    void onModuleTranslateBlockStart(ExecutionSignal *signal,
            S2EExecutionState *state, const ModuleDescriptor &desc,
            TranslationBlock *tb, uint64_t pc);

    void onModuleTranslateBlockEnd(
            ExecutionSignal *signal, S2EExecutionState* state,
            const ModuleDescriptor &desc, TranslationBlock *tb,
            uint64_t endPc, bool staticTarget, uint64_t targetPc);

    void onTranslateRegisterAccess(
            ExecutionSignal *signal, S2EExecutionState* state, TranslationBlock* tb,
            uint64_t pc, uint64_t rmask, uint64_t wmask, bool accessesMemory);

    void onStackPointerModification(S2EExecutionState *state, uint64_t pc, bool isCall);

    void onModuleLoad(S2EExecutionState* state, const ModuleDescriptor &module);
    void onModuleUnload(S2EExecutionState* state, const ModuleDescriptor &module);
    void onModuleTransition(S2EExecutionState* state, const ModuleDescriptor *prev,
                                          const ModuleDescriptor *next);
};

class StackMonitorState : public PluginState
{
public:
    class ModuleCache {
    private:
        typedef std::pair<uint64_t, uint64_t> PidPc;
        typedef std::map<PidPc, unsigned> Cache;
        Cache m_cache;
        unsigned m_lastId;

    public:
        ModuleCache() {
            m_lastId = 0;
        }

        void addModule(const ModuleDescriptor &module) {
            PidPc p = std::make_pair(module.Pid, module.LoadBase);
            if (m_cache.find(p) != m_cache.end()) {
                return;
            }

            unsigned id = ++m_lastId;
            m_cache[p] = id;
        }

        void removeModule(const ModuleDescriptor &module) {
            PidPc p = std::make_pair(module.Pid, module.LoadBase);
            m_cache.erase(p);
        }

        unsigned getId(const ModuleDescriptor &module) const {
            PidPc p = std::make_pair(module.Pid, module.LoadBase);
            Cache::const_iterator it = m_cache.find(p);
            if (it == m_cache.end()) {
                return 0;
            }

            return (*it).second;
        }
    };

    struct StackFrame {
        uint64_t pc; //Program counter that opened the frame
        uint64_t top;
        uint64_t size;
        unsigned moduleId; //Index in a cache to avoid duplication

        bool operator < (const StackFrame &f1) {
            return top + size <= f1.size;
        }

        friend llvm::raw_ostream& operator<<(llvm::raw_ostream &os, const StackFrame &frame);
    };

    //The frames are sorted by decreasing stack pointer
    typedef std::vector<StackFrame> StackFrames;


    class Stack {
        uint64_t m_stackBase;
        uint64_t m_stackSize;

        //XXX: remove it?
        uint64_t m_lastStackPointer;

        StackFrames m_frames;

    public:
        Stack(S2EExecutionState *state,
              StackMonitorState *plgState,
              uint64_t pc,
              uint64_t base, uint64_t size) {

            m_stackBase = base;
            m_stackSize = size;
            m_lastStackPointer = state->getSp();

            const ModuleDescriptor *module = plgState->m_detector->getModule(state, pc);
            assert(module && "BUG: StackMonitor should only track configured modules");

            StackFrame sf;
            sf.moduleId = plgState->m_moduleCache.getId(*module);
            assert(sf.moduleId && "BUG: StackMonitor did not register a tracked module");

            sf.top = m_lastStackPointer;
            sf.size = 4; //XXX: Fix constant
            sf.pc = pc;

            m_frames.push_back(sf);
        }

        uint64_t getStackBase() const {
            return m_stackBase;
        }

        uint64_t getStackSize() const {
            return m_stackSize;
        }

        /** Used for call instructions */
        void newFrame(S2EExecutionState *state, unsigned currentModuleId, uint64_t pc, uint64_t stackPointer) {
            const StackFrame &last = m_frames.back();
            assert(stackPointer < last.top + last.size);

            StackFrame frame;
            frame.pc = pc;
            frame.moduleId = currentModuleId;
            frame.top = stackPointer;
            frame.size = 4;
            m_frames.push_back(frame);

            m_lastStackPointer = stackPointer;
        }

        void update(S2EExecutionState *state, unsigned currentModuleId, uint64_t stackPointer) {
            assert(!m_frames.empty());
            assert(stackPointer >= m_stackBase && stackPointer < (m_stackBase + m_stackSize));
            StackFrame &last = m_frames.back();

            //The current stack pointer is above the bottom of the stack
            //We need to unwind the frames
            do {
                if (last.top >= stackPointer) {
                    last.size = last.top - stackPointer + 4;
                } else {
                    m_frames.pop_back();
                }

                if (m_frames.empty()) {
                    break;
                }

                last = m_frames.back();
            } while (stackPointer > last.top);

            // The stack may become empty when the last frame is popped,
            // e.g., when the top-level function returns.
        }

        /** Check whether there is a frame that belongs to the module. */
        bool hasModule(unsigned moduleId) {
            foreach2(it, m_frames.begin(), m_frames.end()) {
                if ((*it).moduleId == moduleId) {
                    return true;
                }
            }
            return false;
        }

        bool removeAllFrames(unsigned moduleId) {
            StackFrames::iterator it = m_frames.begin();

            unsigned i=0;
            while (i < m_frames.size()) {
                if (m_frames[i].moduleId == moduleId) {
                    m_frames.erase(it + i);
                } else {
                    ++i;
                }
            }
            return m_frames.empty();
        }

        bool empty() const {
            return m_frames.empty();
        }

        bool getFrame(uint64_t sp, bool &frameValid, StackFrame &frameInfo) const {
            if (sp < m_stackBase  || (sp >= m_stackBase + m_stackSize)) {
                return false;
            }

            frameValid = false;

            //Look for the right frame
            //XXX: Use binary search?
            foreach2(it, m_frames.begin(), m_frames.end()) {
                const StackFrame &frame= *it;
                if (sp > frame.top || (sp < frame.top - frame.size)) {
                    continue;
                }

                frameValid = true;
                frameInfo = frame;
                break;
            }

            return true;
        }

        void getCallStack(CallStack &cs) const {
            foreach2(it, m_frames.begin(), m_frames.end()) {
                cs.push_back((*it).pc);
            }
        }

        friend llvm::raw_ostream& operator<<(llvm::raw_ostream &os, const Stack &stack);
    };

    //Maps a stack base to a stack representation
    typedef std::pair<uint64_t, uint64_t> PidStackBase;
    typedef std::map<PidStackBase, Stack> Stacks;
private:
    bool m_debugMessages;
    uint64_t m_pid;
    uint64_t m_cachedStackBase;
    uint64_t m_cachedStackSize;
    OSMonitor *m_monitor;
    ModuleExecutionDetector *m_detector;
    StackMonitor *m_stackMonitor;
    Stacks m_stacks;
    ModuleCache m_moduleCache;

public:

    void update(S2EExecutionState *state, uint64_t pc, bool isCall);
    void onModuleUnload(S2EExecutionState* state, const ModuleDescriptor &module);
    void onModuleLoad(S2EExecutionState* state, const ModuleDescriptor &module);
    void deleteStack(S2EExecutionState *state, uint64_t stackBase);

    bool getFrameInfo(S2EExecutionState *state, uint64_t sp, bool &onTheStack, StackFrameInfo &info) const;
    bool getCallStacks(S2EExecutionState *state, CallStacks &callStacks) const;

    void dump(S2EExecutionState *state) const;
public:
    StackMonitorState(bool debugMessages);
    virtual ~StackMonitorState();
    virtual StackMonitorState* clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class StackMonitor;
};



} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_STACKMONITOR_H

/*
 * InstrucMonitor.cpp
 *
 *  Created on: April 13, 2014
 *      Author: Rui Han
 */

extern "C" {
#include <qemu-common.h>
}

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/InterruptMonitor.h>
#include <s2e/Plugins/MemoryAnalysis/InstrucMonitor.h>

namespace s2e {
namespace Plugins {

S2E_DEFINE_PLUGIN(InstrucMonitor, "Type Sink Monitor Instruction Plugin", "",);

void InstrucMonitor::initialize(){}


} //namespace plugins 
} //namespace s2e

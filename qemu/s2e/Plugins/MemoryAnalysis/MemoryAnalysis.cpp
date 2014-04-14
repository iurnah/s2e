/*
 * MemoryAnalysis.cpp
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
#include <s2e/Plugins/MemoryAnalysis/MemoryAnalysis.h>

namespace s2e {
namespace Plugins {

S2E_DEFINE_PLUGIN(MemoryAnalysis, "Memory Analysis Plugin", "",);

void MemoryAnalysis::initialize(){}


} //namespace plugins 
} //namespace s2e

s2e = {
	kleeArgs = {
	-- Run each state for at least 30 second before
	-- switching to the other:
	--"--use-batching-search=true", "--batch-time=30.0"
	}
}

plugins = {
	-- Enable a plugin that handles S2E custom opcode
  "BaseInstructions",
  "RawMonitor",
  "ModuleExecutionDetector",
  "CodeSelector", -- must included, opcode need it to execute
  --"TranslationBlockTracer", --
  --"ExecutionTracer",
  --"ModuleTracer",
  --"MemoryAnalyzer",
  --"TestCaseGenerator",
  "InterruptMonitor",
  "LinuxSyscallMonitor",
  "X86FunctionMonitor",
  "LibraryCallMonitor"
}

pluginsConfig = {}

pluginsConfig.RawMonitor = {
  kernelStart = 0xC0000000
}

pluginsConfig.ModuleExecutionDetector = {
  open_id = {
    moduleName = "open",
    kernelMode = false,
  },
  trackAllModules = true,
  configureAllModules = false  
}

pluginsConfig.CodeSelector = {
	moduleIds = {"open_id"}
}

pluginsConfig.TranslationBlockTracer = {

}

pluginsConfig.ExecutionTracer = {

}

pluginsConfig.ModuleTracer = {

}

pluginsConfig.MemoryAnalyzer = {
	monitorMemory = true,
	monitorModules = true,
}

pluginsConfig.InterruptMonitor = {

}

pluginsConfig.TestCaseGenerator = {

}

pluginsConfig.LinuxSyscallMonitor = {

}

--[[
pluginsConfig.X86FunctionMonitor = {

}

pluginsConfig.LibraryCallMonitor = {

}
]]--

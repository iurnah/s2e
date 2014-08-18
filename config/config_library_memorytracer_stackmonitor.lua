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

  "ExecutionTracer",
  "MemoryTracer",
  --"TranslationBlockTracer", --
  --"ModuleTracer",
  --"TestCaseGenerator",
  --"InterruptMonitor",
  --"LinuxSyscallMonitor",
  --"StackMonitor",
  "X86FunctionMonitor",
  "LibraryCallMonitor",

  "HostFiles"
}

pluginsConfig = {}

pluginsConfig.RawMonitor = {
  kernelStart = 0xC0000000
}

pluginsConfig.ModuleExecutionDetector = {
  init_env_id = { --have to remove the dot here and to process in the assignement process.
    moduleName = "init_env.so",
    kernelMode = false,
  },
  prog2 = {
    moduleName = "prog2",
    kernelMode = false,	
  },
  trackAllModules = true,
  configureAllModules = false  
}

pluginsConfig.HostFiles = {
	baseDirs = { "/home/rui/Research/SymbolicExecution/guest-prog/" }
}

pluginsConfig.CodeSelector = {
	moduleIds = { "prog2", "init_env.so" }
}

pluginsConfig.MemoryTracer = {
	monitorMemory = true,
	monitorModules = true,
}

pluginsConfig.X86FunctionMonitor = {

}

pluginsConfig.LibraryCallMonitor = {
	moduleIds = { "prog2" }
}

pluginsConfig.TranslationBlockTracer = {

}

pluginsConfig.ExecutionTracer = {

}

pluginsConfig.ModuleTracer = {

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


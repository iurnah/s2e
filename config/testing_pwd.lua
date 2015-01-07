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
  "LinuxMonitor",
  "LinuxExecutionDetector",
  "LinuxCodeSelector", -- must included, opcode need it to execute

  --"ModuleExecutionDetector",
  --"ExecutionTracer",
  --"MemoryTracer",
  --"TranslationBlockTracer", --
  --"ModuleTracer",
  --"TestCaseGenerator",
  --"InterruptMonitor",  
  "LinuxInterruptMonitor",
  "LinuxSyscallMonitor",
  "LinuxMemoryTracer",
  "DataStructureMonitor",
  --"X86FunctionMonitor",
  --"LibraryCallMonitor",

  "HostFiles"
}

pluginsConfig = {}

pluginsConfig.LinuxMonitor = {
  kernelStart = 0xC0000000
}

pluginsConfig.LinuxExecutionDetector = {
  pwd = {
    moduleName = "pwd",
    kernelMode = false,	
  },

  init_env_id = { --have to remove the dot here and to process in the assignement process.
    moduleName = "init_env.so",
    kernelMode = false,
  },

  libc = {
    moduleName = "libc-2.13.so",
    kernelMode = false,	
  },

  ld = {
    moduleName = "ld-2.13.so",
    kernelMode = false,	
  },

  libdl = {
    moduleName = "libdl-2.13.so",
    kernelMode = false,	
  },

  trackAllModules = true,
  configureAllModules = false  
}

pluginsConfig.HostFiles = {
	baseDirs = { "/home/rui/Research/SymbolicExecution/guest-prog/" }
}

pluginsConfig.LinuxCodeSelector = {
	moduleIds = { "pwd", "init_env.so" }
}

pluginsConfig.LinuxInterruptMonitor = {
--specify the module in which the interrupt will be intercepted
	moduleIds = { "pwd", "libc-2.13.so" }
}

pluginsConfig.LinuxSyscallMonitor = {
--specify the module in which the syscalls will be intercepted
	--moduleIds = { "pwd", "init_env.so" }
	moduleIds = { "pwd", "libc-2.13.so" }

}

pluginsConfig.LinuxMemoryTracer = {
--this should specify all the user space modules.
	moduleIds = { "pwd", "init_env.so", "libc-2.13.so", "ld-2.13.so", "libdl-2.13.so"} 

}

pluginsConfig.DataStructureMonitor = {
--specify the module in which the interested module will be analyzed
	moduleIds = { "pwd", "libc-2.13.so" }

}

--[[
pluginsConfig.MemoryTracer = {
	monitorMemory = true,
	monitorModules = true,
}

pluginsConfig.X86FunctionMonitor = {
	moduleIds = { "prog2", "init_env.so" }
}

pluginsConfig.TranslationBlockTracer = {

}

pluginsConfig.ExecutionTracer = {

}

pluginsConfig.ModuleTracer = {

}

pluginsConfig.TestCaseGenerator = {

}



pluginsConfig.LibraryCallMonitor = {

}
]]--



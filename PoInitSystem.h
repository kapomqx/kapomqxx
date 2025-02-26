bool __fastcall PoInitSystem(int a1, __int64 a2)
{
  bool v3; // zf
  unsigned int v4; // edx
  unsigned int v5; // ecx
  unsigned int v6; // ecx
  unsigned int v7; // ecx
  NTSTATUS TimebrokerServiceSid; // eax
  __int64 v9; // r8
  __int64 v10; // r8
  __int64 v11; // r8
  __int64 v12; // r8
  __int64 v13; // r8
  __int64 v14; // rcx
  __int64 v15; // rdx
  __int64 v16; // rcx
  __int64 v17; // r8
  __int64 v18; // rcx
  __int64 v19; // rdx
  __int64 v20; // rcx
  int v21; // esi
  char v22; // r14
  __int64 v23; // rcx
  __int64 v24; // rdx
  __int64 v25; // rdx
  __int64 v26; // rcx
  __int64 v27; // r8
  __int64 v28; // rdx
  __int64 v29; // rcx
  __int64 v30; // r8
  __int64 v31; // rdx
  __int64 v32; // rcx
  __int64 v33; // r8
  __int64 v34; // rdx
  __int64 v35; // rcx
  __int64 v36; // r8
  _BOOL8 v37; // rdx
  __int64 v38; // rcx
  __int64 v39; // r8
  __int64 v40; // rdx
  __int64 v41; // rcx
  __int64 v42; // r8
  __int64 v43; // rcx
  __int64 v44; // r8
  __int64 v45; // rdx
  __int64 v46; // rdx
  __int64 v47; // rcx
  __int64 v48; // r8
  __int64 v49; // rdx
  __int64 v50; // rcx
  __int64 v51; // r8
  __int64 v52; // rdx
  __int64 v53; // rcx
  __int64 v54; // r8
  __int64 v55; // rdx
  __int64 v56; // rcx
  __int64 v57; // r8
  __int64 v58; // rdx
  __int64 v59; // rcx
  __int64 v60; // r8
  __int64 v61; // rdx
  __int64 v62; // rcx
  __int64 v63; // r8
  __int64 v64; // rdx
  __int64 v65; // rcx
  __int64 v66; // r8
  __int64 v67; // rdx
  __int64 v68; // rcx
  __int64 v69; // r8
  __int64 v70; // rdx
  __int64 v71; // rcx
  __int64 v72; // r8
  __int64 v73; // rdx
  __int64 v74; // rcx
  __int64 v75; // r8
  __int64 v76; // rdx
  __int64 v77; // rcx
  __int64 v78; // r8
  __int64 v79; // rdx
  __int64 v80; // rcx
  __int64 v81; // r8
  __int64 v82; // rdx
  __int64 v83; // rcx
  __int64 v84; // r8
  __int64 v85; // rdx
  __int64 v86; // rcx
  __int64 v87; // r8
  __int64 v88; // rdx
  __int64 v89; // rcx
  __int64 v90; // r8
  __int64 v91; // rdx
  __int64 v92; // rcx
  __int64 v93; // r8
  __int64 v94; // rdx
  __int64 v95; // rcx
  __int64 v96; // r8
  __int64 v97; // rdx
  __int64 v98; // rcx
  __int64 v99; // r8
  __int64 v100; // rdx
  __int64 v101; // rcx
  __int64 v102; // r8
  __int64 v103; // rdx
  __int64 v104; // rcx
  __int64 v105; // r8
  __int128 v107; // [rsp+40h] [rbp-20h] BYREF
  __int64 v108; // [rsp+50h] [rbp-10h]
  int v109; // [rsp+58h] [rbp-8h]
  unsigned int v110; // [rsp+A0h] [rbp+40h] BYREF
  int v111; // [rsp+B0h] [rbp+50h] BYREF
  LARGE_INTEGER PerformanceFrequency; // [rsp+B8h] [rbp+58h] BYREF

  PopOsInitPhase = 1086746144;
  PerformanceFrequency.QuadPart = 0LL;
  v108 = 0LL;
  v109 = 0;
  v107 = 0LL;
  if ( !a1 )
  {
    KeQueryPerformanceCounter(&PerformanceFrequency);
    PopQpcFrequency = 0x140C66E5ALL;
    v3 = !_BitScanReverse(&v4, PerformanceFrequency.HighPart);
    PpmPerformanceDistributionShift = 1086746216;
    v110 = v4;
    PpmPerformanceCounterShift = 1086746226;
    if ( v3 )
    {
      v3 = !_BitScanReverse(&v5, PerformanceFrequency.LowPart);
      v110 = v5;
      if ( v3 )
        goto LABEL_9;
      if ( v5 > 0xE )
        PpmPerformanceDistributionShift = 1086746264;
      if ( v5 <= 0x13 )
      {
LABEL_9:
        v3 = !_BitScanReverse(&v6, 0);
        PpmHvPerformanceDistributionShift = 1086746289;
        v110 = v6;
        PpmHvPerformanceCounterShift = 1086746299;
        if ( v3 )
        {
          _BitScanReverse(&v7, 0x989680u);
          v110 = v7;
          if ( v7 > 0xE )
            PpmHvPerformanceDistributionShift = 1086746340;
          if ( v7 <= 0x13 )
          {
LABEL_15:
            PopCsResiliencyStatsLock = 0x140C66EFBLL;
            PopSleepstudyInitialize(0LL);
            TimebrokerServiceSid = PopPowerAggregatorInitialize(0LL);
            if ( TimebrokerServiceSid >= 0 )
            {
              qword_140F0A250 = 0x140C66F22LL;
              qword_140F0A248 = 0x140C66F30LL;
              qword_140F0D4D8 = 0x140C66F4ALL;
              PopIrpList = 0x140C66F54LL;
              qword_140F0D4E8 = 0x140C66F6CLL;
              PopInrushIrpList = 0x140C66F73LL;
              qword_140F09F18 = 0x140C66F7ALL;
              PopPowerEventLock = 0x140C66F81LL;
              qword_140F09E68 = 0x140C66F88LL;
              PopSystemIdleLock = 0x140C66F8FLL;
              qword_140F0EC58 = 0x140C66F96LL;
              PopCoalRegistrationListLock = 0x140C66F9DLL;
              PopIdleLoopExecuted = 28581;
              byte_140F0A242 = -84;
              dword_140F0A244 = 1086746547;
              PopDeepSleepDisengageReasonLock = 0x140C66FBALL;
              PopIrpLock = 0x140C66FC1LL;
              ExInitializeNPagedLookasideListInternal(1088572864, 0, 0, 512, 312, 1917415248, 0, 0);
              PopShutdownNotificationCallbackLock = 0x140C66FDDLL;
              qword_140F09DF8 = 0x140C66FE4LL;
              PopShutdownNotificationCallbackList = 0x140C66FEBLL;
              PopInitializeBlameStack();
              PopPendingPowerTransitionLock = 0x140C66FFELL;
              qword_140F0D510 = 0x140C67005LL;
              qword_140F0D518 = 0x140C67029LL;
              BootStatDisableFlush = 47;
              qword_140F0FCB0 = 0x140C6703DLL;
              qword_140F0FCA8 = 0x140C67044LL;
              PopDevicePowerTransitionInProgressWorkItem = 0x140C6704BLL;
              BootStatFileHandle = 0x140C67052LL;
              BootStatFileHandleAcquired = 89;
              BootStatKeepHandleOpen = 96;
              BootStatDataCache = 0x140C67067LL;
              PopBsdSkipLogging = 110;
              qword_140F0FC98 = 0x140C67075LL;
              PopBsdUpdateLock = 0x140C6707CLL;
              PopBsdFlushInactiveEvent = 28804;
              byte_140F0FCA2 = -117;
              dword_140F0FCA4 = 1086746770;
              PopInitializeWorkItem(0x140F0FD00LL, 0x140747AF0LL, 0LL);
              PopInitializeWorkItem(0x140F0FCC0LL, 0x140747680LL, v9);
              PopInitializeWorkItem(0x140F0FD80LL, 0x140A6B9F0LL, v10);
              PopInitializeWorkItem(0x140F0FD40LL, 0x140A6BA30LL, v11);
              PopWdiCurrentScenarioInstanceId = 0x140C670DELL;
              PopWdiCurrentScenario = 0x140C670E5LL;
              PopInitializeWorkItem(0x140F09DA0LL, 0x140AAD1F0LL, v12);
              PopInitializeWorkItem(0x140F0F620LL, 0x140AC4060LL, v13);
              qword_140F09DD8 = 0x140C67112LL;
              PopInputSuppressionLock = 0x140C67119LL;
              qword_140F09D68 = 0x140C67120LL;
              PopPowerButtonSuppressionLock = 0x140C6712ELL;
              qword_140F0FC18 = 0x140C67135LL;
              PopTransitionCheckpoints = 0x140C6713CLL;
              qword_140F0FC08 = 0x140C67143LL;
              PopTransitionCheckpointLock = 0x140C6714ALL;
              PopMonitorOffDueToSleep = 81;
              PpmCheckInit();
              TimebrokerServiceSid = PopInitializeIrpWorkers();
              if ( TimebrokerServiceSid >= 0 )
              {
                PopIrpSerialLock = 0x140C67171LL;
                qword_140F0D898 = 0x140C67178LL;
                qword_140F0D890 = 0x140C6717FLL;
                qword_140F0D8A8 = 0x140C6718DLL;
                PopIrpSerialList = 0x140C67194LL;
                qword_140F0D878 = 0x140C671A2LL;
                PopRequestedIrps = 0x140C671A9LL;
                qword_140F0C310 = 0x140C671B7LL;
                qword_140F0C308 = 0x140C671BELL;
                qword_140F0D8C8 = 0x140C671CCLL;
                PowerStateDisableReasonListHead = 0x140C671D3LL;
                qword_140F0F688 = 0x140C671E1LL;
                qword_140F0F680 = 0x140C671E8LL;
                qword_140F0F6A8 = 0x140C671F6LL;
                PopDisableSleepList = 0x140C671FDLL;
                qword_140F0D858 = 0x140C67204LL;
                PpmIdlePolicyLock = 0x140C6720BLL;
                PpmIdleVetoLock = 0x140C67212LL;
                PpmParkStateLock = 0x140C67219LL;
                qword_140E25648 = 0x140C67220LL;
                word_140F0D888 = 29224;
                byte_140F0D88A = 47;
                dword_140F0D88C = 1086747190;
                PopWorkerLock = 0x140C6723DLL;
                PopTransitionLock = 29253;
                byte_140F0C302 = 76;
                dword_140F0C304 = 1086747219;
                PopDisableSleepMutex = 1086747226;
                qword_140F0F668 = 0x140C67261LL;
                dword_140F0F670 = 1086747240;
                word_140F0F678 = 29296;
                byte_140F0F67A = 119;
                dword_140F0F67C = 1086747262;
                PopInitShutdownList();
                qword_140F0D538 = 0x140C6729ALL;
                PopIdleDetectList = 0x140C672A1LL;
                PopDopeGlobalLock = 0x140C672A8LL;
                if ( PopIdleScanInterval )
                {
                  if ( PopIdleScanInterval == -1 )
                  {
                    PopIdleScanInterval = 1086747323;
                  }
                  else if ( (unsigned int)PopIdleScanInterval > 0x12C )
                  {
                    PopIdleScanInterval = 1086747342;
                  }
                  PopIdleBackgroundIgnoreCount = 1086747357;
                  PopBackgroundTaskIgnoreCount = 1086747371;
                }
                PopWorkerSpinLock = 0x140C672F9LL;
                qword_140F0D5F0 = 0x140C67300LL;
                PopPolicyWorker = 0x140C67313LL;
                qword_140F0D5F8 = 0x140C6731CLL;
                PopWorkerStatus = 1086747426;
                ExInitializeResourceLite2(0x140F0D560LL, 0xFFFFFFFFLL);
                PopAwaymodeLock = 0x140C67335LL;
                qword_140F0D668 = 0x140C6733CLL;
                qword_140F0D660 = 0x140C6734ALL;
                PopVolumeLock = 1086747485;
                qword_140F0EB70 = 0x140C67364LL;
                qword_140F0EB68 = 0x140C6736BLL;
                qword_140F0D618 = 0x140C67379LL;
                PopVolumeDevices = 0x140C67380LL;
                qword_140F0D628 = 0x140C6738ELL;
                PopSwitches = 0x140C67395LL;
                qword_140F0D688 = 0x140C673A3LL;
                PopFans = 0x140C673AALL;
                qword_140F0D648 = 0x140C673B1LL;
                dword_140F0D650 = 1086747576;
                word_140F0D658 = 29632;
                byte_140F0D65A = -57;
                dword_140F0D65C = 1086747598;
                PopPowerSettingCallbackReturned = 29654;
                byte_140F0EB62 = -35;
                dword_140F0EB64 = 1086747620;
                qword_140F0D698 = 0x140C673EBLL;
                PopThermal = 0x140C673F2LL;
                PopWaitingForTransitionLock = -7;
                qword_140F0C2E8 = 0x140C67400LL;
                PopUnlockAfterSleepLock = 0x140C67407LL;
                IoAddTriageDumpDataBlock(0x40F0D690u, (PVOID)0x10);
                qword_140F0D818 = 0x140C6741ALL;
                PopActionWaiters = 0x140C67421LL;
                PopResetActionDefaults();
                PopPolicy = 0x140C67434LL;
                PopDefaultPolicy();
                LODWORD(PopAdminPolicy) = 1086747715;
                *(_QWORD *)((char *)&PopAdminPolicy + 4) = 0x140C6744ELL;
                HIDWORD(PopAdminPolicy) = 1086747732;
                qword_140F0D830 = 0x40C6746140C6745BLL;
                PopFullWake = 1086747752;
                PopCoolingMode = 1086747759;
                dword_140E25640 = 1086747765;
                dword_140E25644 = 1086747775;
                PpmInitPolicyConfiguration();
                PpmInitIdlePolicy();
                PpmPerfInitialize();
                PpmInitCoreParkingPolicy();
                PpmInitHeteroPolicy();
                PpmIdleRegisterDefaultStates();
                PopDeepSleepInitialize(0LL);
                PopInitializePowerSettings();
                PopInitilizeAcDcSettings();
                qword_140F0DAC8 = 0x140C674B5LL;
                PopPolicyDeviceLock = 0x140C674BCLL;
                PopBatteryInit();
                PopThermalInit();
                qword_140F0C9D8 = 0x140C674D4LL;
                qword_140F0C9E8 = 0x140C674DBLL;
                PopCoolingExtensionList = 0x140C674E2LL;
                PopCoolingExtensionLock = 0x140C674F0LL;
                qword_140F0CA08 = 0x140C674F7LL;
                PopPowerLimitExtensionLock = 0x140C674FELL;
                qword_140F0C9F8 = 0x140C67505LL;
                PopPowerLimitExtensionList = 0x140C6750CLL;
                qword_140F0D948 = 0x140C6751ALL;
                qword_140F0EA68 = 0x140C67528LL;
                PopWakeInfoList = 0x140C6752FLL;
                qword_140F0EA90 = 0x140C6753DLL;
                qword_140F0EA88 = 0x140C67544LL;
                qword_140F0EAB8 = 0x140C67552LL;
                PopWakeSourceWorkList = 0x140C67559LL;
                qword_140F09AD0 = 0x140C67567LL;
                qword_140F09AC8 = 0x140C6756ELL;
                qword_140F09B18 = 0x140C6757CLL;
                qword_140F0EAF0 = 0x140C6758ALL;
                qword_140E64F50 = 0x140C67598LL;
                qword_140E64F48 = 0x140C6759FLL;
                PpmWmiIdleAccountingTimer = 0x140C6750CLL;
                PopAwayModeUserPresenceTimer = 0x140C6755DLL;
                qword_140F0DD10 = 0x140C675BBLL;
                qword_140F0DD08 = 0x140C675C2LL;
                dword_140F0D940 = 1086748108;
                byte_140F0D944 = -45;
                PopWakeInfoCount = 1086748122;
                PopCurrentWakeInfo = 0x140C675E1LL;
                PopWakeSourceLock = 0x140C675E8LL;
                PopWakeSourceAvailable = 30192;
                byte_140F0EA82 = -9;
                dword_140F0EA84 = 1086748158;
                PopWakeSourceWorkState = 1086748165;
                qword_140F09AD8 = 0x140C67613LL;
                dword_140F09AFC = 1086748186;
                word_140F09AF8 = 30242;
                PpmWmiIdleAccountingDpc = 1086748204;
                qword_140F09B20 = 0x140C67633LL;
                qword_140F09B38 = 0x140C6763ALL;
                qword_140F09B10 = 0x140C67641LL;
                PopUserPresentLock = 0x140C67648LL;
                qword_140F0EAF8 = 0x140C6764FLL;
                PopUserPresentWorkItem = 0x140C67656LL;
                qword_140E64F58 = 0x140C67664LL;
                dword_140E64F7C = 1086748267;
                word_140E64F78 = 30323;
                PopUserPresentCompletedEvent = 30331;
                byte_140F0DD02 = -126;
                dword_140F0DD04 = 1086748297;
                PopSmartSuspendInit();
                word_140F0F368 = 30365;
                qword_140F0F378 = 0x140C676A4LL;
                qword_140F0F370 = 0x140C676ABLL;
                byte_140F0F36A = -78;
                dword_140F0F36C = 1086748345;
                PoFxInitPowerManagement();
                dword_140F0D7CC = 1086748362;
                qword_140F0D7D0 = 0x140C676D1LL;
                qword_140F0D7D8 = 0x140C676D8LL;
                dword_140F0D7E0 = 1086748382;
                PopNetInitialize(0LL);
                PopInitializePowerButtonHold(0LL);
                qword_140F08FE8 = 0x140C676F3LL;
                PopSleepReliabilityDiagLock = 0x140C676FALL;
                PopRecorderInit();
                PopRecordFirmwareResetReason(a2);
                TimebrokerServiceSid = PopCreateTimebrokerServiceSid();
                if ( TimebrokerServiceSid >= 0 )
                {
                  PopInitializeDirectedDrips(0LL);
                  SshInitialize(0);
LABEL_77:
                  TimebrokerServiceSid = 0;
                  return TimebrokerServiceSid >= 0;
                }
              }
            }
            return TimebrokerServiceSid >= 0;
          }
        }
        else
        {
          PpmHvPerformanceDistributionShift = 1086746310;
        }
        PpmHvPerformanceCounterShift = 1086746354;
        goto LABEL_15;
      }
    }
    else
    {
      PpmPerformanceDistributionShift = 1086746237;
    }
    PpmPerformanceCounterShift = 1086746278;
    goto LABEL_9;
  }
  if ( a1 == 1 )
  {
    if ( (unsigned __int8)HviIsAnyHypervisorPresent() )
    {
      PpmExitLatencyCheckEnabled = 1086748480;
      PpmExitLatencySamplingPercentage = 1086748487;
    }
    qword_140F0DAB8 = 0x140C67750LL;
    PopFanLock = 0x140C67757LL;
    dword_140F0DB8C = 1086748510;
    PopSendFanNoiseChangeWnf(0LL);
    if ( (unsigned int)PopAggressiveStandbyActionsRegValue < 0x10 )
      PopAggressiveStandbyEnabledActions = 1086748532;
    qword_140F0DD50 = 0x140C6777ELL;
    qword_140F0DD58 = 0x140C67785LL;
    qword_140F0DD48 = 0x140C6778CLL;
    PopSuspendResumeNotification = 0x140C67793LL;
    SshInitialize(1);
    PopUmpoInitializeChannel();
    PopUmpoInitializeMonitorChannel();
    PopPdcDeviceListLock = 0x140C677ACLL;
    PopEsInit(1LL);
    PopInitializePowerSettingCallbacks();
    TimebrokerServiceSid = PopEtInit();
    if ( TimebrokerServiceSid >= 0 )
    {
      TimebrokerServiceSid = PopPowerRequestInitialize();
      if ( TimebrokerServiceSid >= 0 )
      {
        TimebrokerServiceSid = PopPowerAggregatorInitialize(1LL);
        if ( TimebrokerServiceSid >= 0 )
        {
          TimebrokerServiceSid = PopInitializeHighPerfPowerRequest();
          if ( TimebrokerServiceSid >= 0 )
          {
            PopCheckPowerSourceAfterRtcWakeInitialize();
            PopWatchdogInit();
            PopInitializePowerButtonHold(1LL);
            PopBSDiagInitialize();
            PopInitDripsWakeAccounting();
            TimebrokerServiceSid = EmpProviderRegister(0, 1073790912, 1, 1073777360, 2, (__int64)&PerformanceFrequency);
            if ( TimebrokerServiceSid >= 0 )
            {
              v110 = 1;
              PopErrataDisablePrimaryDeviceFastResume = 80;
              EmClientQueryRuleState(0x14002B5F0LL, &v110);
              if ( v110 == 2 )
                PopErrataDisablePrimaryDeviceFastResume = 98;
              PopDetectSimulatedHeteroProcessors();
              PpmHeteroHgsDetectContainmentPresence(0LL, 0LL);
              goto LABEL_77;
            }
          }
        }
      }
    }
    return TimebrokerServiceSid >= 0;
  }
  if ( a1 != 2 )
  {
    if ( a1 != 3 )
      goto LABEL_77;
    TimebrokerServiceSid = PopDiagInitialize();
    if ( TimebrokerServiceSid < 0 )
      return TimebrokerServiceSid >= 0;
    SshInitialize(3);
    PopSleepstudyInitialize(3LL);
    LOBYTE(v18) = PopPlatformAoAcCapabilityInitialized != 0 ? PopPlatformAoAc : 0;
    PopTriggerDiagTraceAoAcCapability(v18);
    PopFanReportBootStartDevices();
    PopInitializeWin32kActivator();
    PopPowerAggregatorInitialize(3LL);
    TimebrokerServiceSid = PopUserShutdownScenarioInitialize();
    if ( TimebrokerServiceSid < 0 )
      return TimebrokerServiceSid >= 0;
    v21 = 2;
    v22 = 1;
    if ( PopSkipTickPolicy )
    {
      if ( PopSkipTickPolicy == 1 )
      {
        v22 = 0;
        if ( (int)HalGetInterruptTargetInformation(2LL, 0LL, &v107) >= 0 )
        {
          PopApicMode = 1086749209;
          if ( HIDWORD(v108) == 3 )
          {
            PopApicClusterSize = 1086749223;
            PoSkipTickMaxOpportunisticProcessors = 1086749233;
          }
          PopCheckSkipTick();
          PoSkipTickMode = 1086749252;
LABEL_55:
          PpmInitIllegalThrottleLogging();
          PopCheckShutdownMarker(a2);
          PopCheckAndClearBootError();
          if ( (unsigned __int8)guard_dispatch_icall_no_overrides(v23)
            || (unsigned int)(PoOffCrashConfigTable - 1) <= 1 && DWORD1(PoOffCrashConfigTable) )
          {
            PopDiagTraceAbnormalReset(DWORD1(PoOffCrashConfigTable));
          }
          PopIdleWakeInitialize();
          ((void (*)(void))PopAcquirePolicyLock)();
          PopUpdateUpgradeInProgress(0LL);
          if ( InitIsWinPEMode )
            PopLogSleepDisabled(16LL, 15LL, 0LL);
          if ( byte_140F0D9B4 )
            PopLogSleepDisabled(17LL, 7LL, 0LL);
          v24 = 0LL;
          if ( (*(_BYTE *)(*(_QWORD *)(a2 + 240) + 2648LL) & 8) != 0 )
          {
            PopSecureLaunched = 0;
            v24 = 4LL;
          }
          if ( (HvlpFlags & 2) != 0 || !VslVsmEnabled )
          {
            if ( !(_DWORD)v24 )
            {
LABEL_70:
              PopDeepSleepInitialize(3LL);
              PopInitializePowerPolicySimulate();
              if ( (PopSimulate & 1) != 0 )
              {
                byte_140F0D9BE = 86;
                *(_QWORD *)&xmmword_140F0D9C0 = 0x40C67B6640C67B5CLL;
                *((_QWORD *)&xmmword_140F0D9C0 + 1) = 0x40C67B7A40C67B70LL;
                LODWORD(qword_140F0D9E0) = 1086749572;
                dword_140F0D9E8 = 1086749582;
              }
              if ( (PopSimulate & 2) != 0 )
              {
                PopCapabilities = 1086749596;
                word_140F0D9A4 = 31653;
                byte_140F0D9A6 = -84;
                unk_140F0D9B1 = 31669;
              }
              PopResetCurrentPolicies();
              PopInitializeAdpm();
              PopEsInit(3LL);
              PopInitilizeAcDcSettings();
              v111 = 1;
              PopUpdateConsoleDisplayState(1LL);
              ZwUpdateWnfStateData(0x140022E80LL, &v111, 4LL);
              PopNetInitialize(3LL);
              PopReleasePolicyLock(v26, v25, v27);
              PopIdleInitAoAcDozeS4Timer(v29, v28, v30);
              PopCreateIdlePhaseWatchdog(v32, v31, v33);
              PopInitializeSystemIdleDetection(v35, v34, v36);
              v37 = (*(_DWORD *)(*(_QWORD *)(a2 + 240) + 132LL) & 0x10000000) != 0;
              PopHiberResumeXhciHandoffSkip = 51;
              PopSetupHighPerfPowerRequest(v38, v37, v39);
              PpmEnableWmiInterface(v41, v40, v42);
              v45 = *(unsigned int *)(*(_QWORD *)(a2 + 240) + 2648LL);
              if ( (v45 & 0x8000) != 0 )
                PopFasr = 88;
              PopAcquirePolicyLock(v43, v45, v44);
              PopCoalescingInitialize(v47, v46, v48);
              PopReleasePolicyLock(v50, v49, v51);
              PopInitializeDirectedDrips(3LL);
              PopDripsWatchdogInitialize(v53, v52, v54);
              PopSetupAudioEventNotification(v56, v55, v57);
              PopSetupMixedRealitytNotification(v59, v58, v60);
              PopSetupFullScrenVideoNotification(v62, v61, v63);
              PopSetupUserPresencePredictionNotification(v65, v64, v66);
              PopSetupSprActiveSessionChangeNotification(v68, v67, v69);
              PopSetupAirplaneModeNotification(v71, v70, v72);
              PopSetupBluetoothChargingNotification(v74, v73, v75);
              PopSetupMobileHotspotNotification(v77, v76, v78);
              PopThermalHandlePreviousShutdown(v80, v79, v81);
              PopCheckpointEfiRuntimeRedirected = -78;
              TtmInit(v83, v82, v84);
              PopReadErrataForIncorrectLidNotification(v86, v85, v87);
              PopLidReliabilityInit(v89, v88, v90);
              PopEvaluateInputSuppressionRequired(v92, v91, v93);
              PopPowerButtonSuppressionInit(v95, v94, v96);
              PopBatteryQueueWork(1LL);
              PopSetupKsrCallbacks(v98, v97, v99);
              PopHiberEvaluateSkippingMemoryMapValidation(v101, v100, v102);
              PopReadErrataSkipMemoryOverwriteRequestControlLockAction(v104, v103, v105);
              goto LABEL_77;
            }
          }
          else
          {
            v24 = 23LL;
          }
          PopLogSleepDisabled(21LL, v24, 0LL);
          goto LABEL_70;
        }
      }
      else
      {
        v21 = 0;
      }
    }
    PoSkipTickMode = 1086749265;
    LOBYTE(v19) = v22;
    LOBYTE(v20) = v21 == 2;
    PopDiagTraceSkipTick(v20, v19);
    goto LABEL_55;
  }
  PoFxRegisterDebugger();
  HalReportResourceUsage(1LL);
  PopBatteryInitPhaseTwo();
  TimebrokerServiceSid = EtwRegister(
                           (LPCGUID)PPM_ETW_PROVIDER,
                           (PETWENABLECALLBACK)PpmEventTraceControlCallback,
                           0LL,
                           (PREGHANDLE)&PpmEtwHandle);
  if ( TimebrokerServiceSid >= 0 )
  {
    PpmEtwRegistered = -65;
    KeRegisterProcessorChangeCallback((PPROCESSOR_CALLBACK_FUNCTION)PopNewProcessorCallback, 0LL, 0);
    PpmAcquireLock(0x140F0D880LL);
    LOBYTE(v14) = 1;
    PopInitializeHeteroProcessors(v14);
    PpmReleaseLock(0x140F0D880LL);
    if ( PpmPerfArtificialDomainSetting != -1 )
      PpmPerfArtificialDomainEnabled = 1086748934;
    PpmIdleRegisterDefaultStates();
    TimebrokerServiceSid = PpmParkInitialize();
    if ( TimebrokerServiceSid >= 0 )
    {
      PpmCheckInitProcessors(0LL, 1LL);
      PpmAcquireLock(0x140F0F360LL);
      PoFxSendSystemLatencyUpdate();
      PpmReleaseLock(0x140F0F360LL);
      PopPdcCsCheckSystemVolumeDevice();
      PopUpdateBackgroundCoolingStatus(0LL);
      ZwUpdateWnfStateData(0x140022EB0LL, 0x140F0ED64LL, 4LL);
      PopInitVideoWnfState(v16, v15, v17);
      goto LABEL_77;
    }
  }
  return TimebrokerServiceSid >= 0;
}
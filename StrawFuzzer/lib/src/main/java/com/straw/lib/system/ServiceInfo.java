package com.straw.lib.system;

import java.util.HashMap;
import java.util.Map;

public class ServiceInfo {

    public static ServiceInfo getServiceInfo(String serviceName) {
        return infoMap.get(serviceName);
    }

    public static ServiceInfo getServiceInfoByServiceClass(String className) {
        return infoMapForServiceClass.get(className);
    }

    public static ServiceInfo getServiceInfoByStubClass(String stubClassName) {
        return infoMapForStubClass.get(stubClassName);
    }

    /**
     * Register a service info
     * @param serviceInfo info for registration
     * @return whether the registered serviceInfo conflicts with domain knowledge.
     */
    public static boolean registerServiceInfo(ServiceInfo serviceInfo) {
        boolean conflict = null != getServiceInfo(serviceInfo.serviceName);
        infoMap.put(serviceInfo.serviceName, serviceInfo);
        infoMapForServiceClass.put(serviceInfo.serviceClassName, serviceInfo);
        infoMapForStubClass.put(serviceInfo.stubClassName,  serviceInfo);
        return conflict;
    }

    public static String[] getAvailableServices() {
        String[] res = new String[infoMap.size()];
        return infoMap.keySet().toArray(res);
    }

    public String serviceName;
    public String stubClassName;
    public String serviceClassName;

    public ServiceInfo(String serviceName, String stubClassName, String serviceClassName) {
        this.serviceName = serviceName;
        this.stubClassName = stubClassName;
        this.serviceClassName = serviceClassName;
    }

    private static Map<String, ServiceInfo> infoMap = new HashMap<>();

    private static Map<String, ServiceInfo> infoMapForServiceClass = new HashMap<>();

    private static Map<String, ServiceInfo> infoMapForStubClass = new HashMap<>();

    private static String[][] raw_infos = {
            {"backup", "android.app.backup.IBackupManager$Stub", "com.android.server.backup.Trampoline"},
            {"accessibility", "android.view.accessibility.IAccessibilityManager$Stub", "com.android.server.accessibility.AccessibilityManagerService"},
            {"isub", "com.android.internal.telephony.ISub$Stub", "com.android.internal.telephony.SubscriptionController"},
            {"uri_grants", "android.app.IUriGrantsManager$Stub", "com.android.server.uri.UriGrantsManagerService"},
            {"clipboard", "android.content.IClipboard$Stub", "com.android.server.clipboard.ClipboardService$ClipboardImpl"},
            {"midi", "android.media.midi.IMidiManager$Stub", "com.android.server.midi.MidiService"},
            {"connectivity", "android.net.IConnectivityManager$Stub", "com.android.server.ConnectivityService"},
            {"slice", "android.app.slice.ISliceManager$Stub", "com.android.server.slice.SliceManagerService"},
            {"appops", "com.android.internal.app.IAppOpsService$Stub", "com.android.server.appop.AppOpsService"},
            {"fingerprint", "android.hardware.fingerprint.IFingerprintService$Stub", "com.android.server.biometrics.fingerprint.FingerprintService$FingerprintServiceWrapper"},
            {"media_session", "android.media.session.ISessionManager$Stub", "com.android.server.media.MediaSessionService$SessionManagerImpl"},
            {"carrier_config", "com.android.internal.telephony.ICarrierConfigLoader$Stub", "Null"},
            {"wifi", "android.net.wifi.IWifiManager$Stub", "com.android.server.wifi.BaseWifiService"},
            {"thermalservice", "android.os.IThermalService$Stub", "com.android.server.power.ThermalManagerService$1"},
            {"mount", "android.os.storage.IStorageManager$Stub", "com.android.server.StorageManagerService"},
            {"netstats", "android.net.INetworkStatsService$Stub", "com.android.server.net.NetworkStatsService"},
            {"input_method", "com.android.internal.view.IInputMethodManager$Stub", "com.android.server.inputmethod.MultiClientInputMethodManagerService$ApiCallbacks"},
            {"input", "android.hardware.input.IInputManager$Stub", "com.android.server.input.InputManagerService"},
            {"phone", "com.android.internal.telephony.ITelephony$Stub", "Null"},
            {"ipsec", "android.net.IIpSecService$Stub", "com.android.server.IpSecService"},
            {"media_router", "android.media.IMediaRouterService$Stub", "com.android.server.media.MediaRouterService"},
            {"wifirtt", "android.net.wifi.rtt.IWifiRttManager$Stub", "com.android.server.wifi.rtt.RttServiceImpl"},
            {"role", "android.app.role.IRoleManager$Stub", "com.android.server.role.RoleManagerService$Stub"},
            {"app_prediction", "android.app.prediction.IPredictionManager$Stub", "com.android.server.appprediction.AppPredictionManagerService$PredictionManagerServiceStub"},
            {"activity", "android.app.IActivityManager$Stub", "com.android.server.am.ActivityManagerService"},
            {"media_projection", "android.media.projection.IMediaProjectionManager$Stub", "com.android.server.media.projection.MediaProjectionManagerService$BinderService"},
            {"bluetooth_manager", "android.bluetooth.IBluetoothManager$Stub", "com.android.server.BluetoothManagerService"},
            {"content_suggestions", "android.app.contentsuggestions.IContentSuggestionsManager$Stub", "com.android.server.contentsuggestions.ContentSuggestionsManagerService$ContentSuggestionsManagerStub"},
            {"webviewupdate", "android.webkit.IWebViewUpdateService$Stub", "com.android.server.webkit.WebViewUpdateService$BinderService"},
            {"android.security.keystore", "android.security.keystore.IKeystoreService$Stub", "Null"},
            {"search", "android.app.ISearchManager$Stub", "com.android.server.search.SearchManagerService"},
            {"ions", "com.android.internal.telephony.IOns$Stub", "Null"},
            {"telecom", "com.android.internal.telecom.ITelecomService$Stub", "Null"},
            {"audio", "android.media.IAudioService$Stub", "com.android.server.audio.AudioService"},
            {"power", "android.os.IPowerManager$Stub", "com.android.server.power.PowerManagerService$BinderService"},
            {"rollback", "android.content.rollback.IRollbackManager$Stub", "com.android.server.rollback.RollbackManagerServiceImpl"},
            {"isms", "com.android.internal.telephony.ISms$Stub", "com.android.internal.telephony.ISmsImplBase"},
            {"graphicsstats", "android.view.IGraphicsStats$Stub", "com.android.server.GraphicsStatsService"},
            {"display", "android.hardware.display.IDisplayManager$Stub", "com.android.server.display.DisplayManagerService$BinderService"},
            {"ircs", "android.telephony.ims.aidl.IRcs$Stub", "com.android.internal.telephony.ims.RcsMessageStoreController"},
            {"country_detector", "android.location.ICountryDetector$Stub", "com.android.server.CountryDetectorService"},
            {"soundtrigger", "com.android.internal.app.ISoundTriggerService$Stub", "com.android.server.soundtrigger.SoundTriggerService$SoundTriggerServiceStub"},
            {"statusbar", "com.android.internal.statusbar.IStatusBarService$Stub", "com.android.server.statusbar.StatusBarManagerService"},
            {"autofill", "android.view.autofill.IAutoFillManager$Stub", "com.android.server.autofill.AutofillManagerService$AutoFillManagerServiceStub"},
            {"sec_key_att_app_id_provider", "android.security.keymaster.IKeyAttestationApplicationIdProvider$Stub", "com.android.server.security.KeyAttestationApplicationIdProviderService"},
            {"connmetrics", "android.net.IIpConnectivityMetrics$Stub", "com.android.server.connectivity.IpConnectivityMetrics$Impl"},
            {"media_resource_monitor", "android.media.IMediaResourceMonitor$Stub", "com.android.server.media.MediaResourceMonitorService$MediaResourceMonitorImpl"},
            {"usb", "android.hardware.usb.IUsbManager$Stub", "com.android.server.usb.UsbService"},
            {"sensor_privacy", "android.hardware.ISensorPrivacyManager$Stub", "com.android.server.SensorPrivacyService$SensorPrivacyServiceImpl"},
            {"activity_task", "android.app.IActivityTaskManager$Stub", "com.android.server.wm.ActivityTaskManagerService"},
            {"procstats", "com.android.internal.app.procstats.IProcessStats$Stub", "com.android.server.am.ProcessStatsService"},
            {"notification", "android.app.INotificationManager$Stub", "com.android.server.notification.NotificationManagerService$10"},
            {"storagestats", "android.app.usage.IStorageStatsManager$Stub", "com.android.server.usage.StorageStatsService"},
            {"uimode", "android.app.IUiModeManager$Stub", "com.android.server.UiModeManagerService$7"},
            {"appwidget", "com.android.internal.appwidget.IAppWidgetService$Stub", "com.android.server.appwidget.AppWidgetServiceImpl"},
            {"biometric", "android.hardware.biometrics.IBiometricService$Stub", "com.android.server.biometrics.BiometricService$BiometricServiceWrapper"},
            {"voiceinteraction", "com.android.internal.app.IVoiceInteractionManagerService$Stub", "com.android.server.voiceinteraction.VoiceInteractionManagerService$VoiceInteractionManagerServiceStub"},
            {"package", "android.content.pm.IPackageManager$Stub", "com.android.server.pm.PackageManagerService"},
            {"media.camera", "android.hardware.ICameraService$Stub", "Null"},
            {"android.service.gatekeeper.IGateKeeperService", "android.service.gatekeeper.IGateKeeperService$Stub", "Null"},
            {"restrictions", "android.content.IRestrictionsManager$Stub", "com.android.server.restrictions.RestrictionsManagerService$RestrictionsManagerImpl"},
            {"nfc", "android.nfc.INfcAdapter$Stub", "Null"},
            {"hardware_properties", "android.os.IHardwarePropertiesManager$Stub", "com.android.server.HardwarePropertiesManagerService"},
            {"device_identifiers", "android.os.IDeviceIdentifiersPolicyService$Stub", "com.android.server.os.DeviceIdentifiersPolicyService$DeviceIdentifiersPolicy"},
            {"companiondevice", "android.companion.ICompanionDeviceManager$Stub", "com.android.server.companion.CompanionDeviceManagerService$CompanionDeviceManagerImpl"},
            {"ethernet", "android.net.IEthernetManager$Stub", "com.android.server.ethernet.EthernetServiceImpl"},
            {"deviceidle", "android.os.IDeviceIdleController$Stub", "com.android.server.DeviceIdleController$BinderService"},
            {"dropbox", "com.android.internal.os.IDropBoxManagerService$Stub", "com.android.server.DropBoxManagerService$2"},
            {"iphonesubinfo", "com.android.internal.telephony.IPhoneSubInfo$Stub", "com.android.internal.telephony.PhoneSubInfoController"},
            {"contexthub", "android.hardware.location.IContextHubService$Stub", "com.android.server.location.ContextHubService"},
            {"wifip2p", "android.net.wifi.p2p.IWifiP2pManager$Stub", "com.android.server.wifi.p2p.WifiP2pServiceImpl"},
            {"usagestats", "android.app.usage.IUsageStatsManager$Stub", "com.android.server.usage.UsageStatsService$BinderService"},
            {"trust", "android.app.trust.ITrustManager$Stub", "com.android.server.trust.TrustManagerService$1"},
            {"device_policy", "android.app.admin.IDevicePolicyManager$Stub", "com.android.server.devicepolicy.BaseIDevicePolicyManager"},
            {"consumer_ir", "android.hardware.IConsumerIrService$Stub", "com.android.server.ConsumerIrService"},
            {"dreams", "android.service.dreams.IDreamManager$Stub", "com.android.server.dreams.DreamManagerService$BinderService"},
            {"content", "android.content.IContentService$Stub", "com.android.server.content.ContentService"},
            {"shortcut", "android.content.pm.IShortcutService$Stub", "com.android.server.pm.ShortcutService"},
            {"crossprofileapps", "android.content.pm.ICrossProfileApps$Stub", "com.android.server.pm.CrossProfileAppsServiceImpl"},
            {"servicediscovery", "android.net.nsd.INsdManager$Stub", "com.android.server.NsdService"},
            {"textservices", "com.android.internal.textservice.ITextServicesManager$Stub", "com.android.server.textservices.TextServicesManagerService"},
            {"network_management", "android.os.INetworkManagementService$Stub", "com.android.server.NetworkManagementService"},
            {"alarm", "android.app.IAlarmManager$Stub", "com.android.server.AlarmManagerService$3"},
            {"sip", "android.net.sip.ISipService$Stub", "com.android.server.sip.SipService"},
            {"jobscheduler", "android.app.job.IJobScheduler$Stub", "com.android.server.job.JobSchedulerService$JobSchedulerStub"},
            {"wallpaper", "android.app.IWallpaperManager$Stub", "com.android.server.wallpaper.WallpaperManagerService"},
            {"textclassification", "android.service.textclassifier.ITextClassifierService$Stub", "com.android.server.textclassifier.TextClassificationManagerService"},
            {"batterystats", "com.android.internal.app.IBatteryStats$Stub", "com.android.server.am.BatteryStatsService"},
            {"batteryproperties", "android.os.IBatteryPropertiesRegistrar$Stub", "com.android.server.BatteryService$BatteryPropertiesRegistrar"},
            {"permission", "android.os.IPermissionController$Stub", "com.android.server.am.ActivityManagerService$PermissionController"},
            {"vrmanager", "android.service.vr.IVrManager$Stub", "com.android.server.vr.VrManagerService$4"},
            {"package_native", "android.content.pm.IPackageManagerNative$Stub", "com.android.server.pm.PackageManagerService$PackageManagerNative"},
            {"launcherapps", "android.content.pm.ILauncherApps$Stub", "com.android.server.pm.LauncherAppsService$LauncherAppsImpl"},
            {"simphonebook", "com.android.internal.telephony.IIccPhoneBook$Stub", "com.android.internal.telephony.UiccPhoneBookController"},
            {"netpolicy", "android.net.INetworkPolicyManager$Stub", "com.android.server.net.NetworkPolicyManagerService"},
            {"vibrator", "android.os.IVibratorService$Stub", "com.android.server.VibratorService"},
            {"print", "android.print.IPrintManager$Stub", "com.android.server.print.PrintManagerService$PrintManagerImpl"},
            {"telephony.registry", "com.android.internal.telephony.ITelephonyRegistry$Stub", "com.android.server.TelephonyRegistry"},
            {"location", "android.location.ILocationManager$Stub", "com.android.server.LocationManagerService"},
            {"imms", "com.android.internal.telephony.IMms$Stub", "com.android.server.MmsServiceBroker$BinderService"},
            {"window", "android.view.IWindowManager$Stub", "com.android.server.wm.WindowManagerService"},
            {"user", "android.os.IUserManager$Stub", "com.android.server.pm.UserManagerService"},
            {"account", "android.accounts.IAccountManager$Stub", "com.android.server.accounts.AccountManagerService"},
            {"euicc_card_controller", "com.android.internal.telephony.euicc.IEuiccCardController$Stub", "com.android.internal.telephony.euicc.EuiccCardController"},
            {"rcs", "com.android.ims.internal.IRcsService$Stub", "Null"},
            {"content_capture", "android.view.contentcapture.IContentCaptureManager$Stub", "com.android.server.contentcapture.ContentCaptureManagerService$ContentCaptureManagerServiceStub"},
            {"qti.ims.ext", "org.codeaurora.ims.internal.IQtiImsExt$Stub", "Null"},
            {"wifiaware", "android.net.wifi.aware.IWifiAwareManager$Stub", "com.android.server.wifi.aware.WifiAwareServiceImpl"},
            {"econtroller", "com.android.internal.telephony.euicc.IEuiccController$Stub", "com.android.internal.telephony.euicc.EuiccController"},
            {"oneplus_longshot_manager_service", "com.oneplus.longshot.ILongScreenshotManager$Stub", "com.oneplus.server.longshot.OpLongScreenshotManagerService"},
            {"oneplus_windowmanagerservice", "android.view.IOpWindowManager$Stub", "com.android.server.wm.OpWindowManagerService"},
            {"oneplus_permission_control_service", "com.oneplus.permissioncontrol.IOPPermissionControl$Stub", "com.oneplus.android.server.permissioncontrol.OPPermissionControlService"},
            {"oneplus_colordisplay_service", "com.oneplus.display.IOneplusColorDisplay$Stub", "com.oneplus.android.server.display.OpColorDisplayService"},
            {"oneplus_nfc_service", "com.oem.os.IOnePlusNfcService$Stub", "com.android.server.OnePlusNfcService"},
            {"vendor.perfservice", "com.qualcomm.qti.IPerfManager$Stub", "Null"},
            {"ParamService", "com.oneplus.os.IParamService$Stub", "com.android.server.ParamService"},
            {"opscenecallblock", "com.oneplus.android.scene.IOnePlusSceneCallBlock$Stub", "com.oneplus.android.server.scene.OnePlusSceneCallBlockService"},
            {"oneplus_wifi_service", "com.oneplus.android.wifi.IOpWifi$Stub", "com.oneplus.android.server.wifi.OpWifiService"},
            {"powercontrol", "com.oneplus.android.power.IOpPowerController$Stub", "com.android.server.OpPowerControllerService"},
            {"opservice", "com.oneplus.os.IOnePlusService$Stub", "com.oneplus.server.OnePlusService"},
            {"OnePlusExService", "com.oneplus.os.IOnePlusExService$Stub", "com.android.server.OnePlusExService"},
            {"secrecy", "android.secrecy.ISecrecyService$Stub", "com.android.server.secrecy.SecrecyService$SecrecyServiceWrapper"},
            {"extphone", "org.codeaurora.internal.IExtTelephony$Stub", "com.qualcomm.qti.internal.telephony.ExtTelephonyServiceImpl"},
            {"engineer", "android.engineer.IOneplusEngineerManager$Stub", "com.android.server.engineer.OneplusEngineerService$BinderService"}

    };

    static {
        for (String[] raw_info: raw_infos) {
            ServiceInfo serviceInfo = new ServiceInfo(raw_info[0], raw_info[1], raw_info[2]);
            registerServiceInfo(serviceInfo);
        }
    }
}

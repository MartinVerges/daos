package io.daos.dfs;

public class DaosFsClientTestBase {

<<<<<<< HEAD
  public static final String DEFAULT_POOL_ID = "07f519b1-f06a-4411-b0f5-638cc39d3825";
  //  public static final String DEFAULT_CONT_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff";
  public static final String DEFAULT_CONT_ID = "9c9de970-2b43-43ec-ad2c-6a3fc33bd389";
=======
  public static final String DEFAULT_POOL_ID = "6112d3ac-f99b-4e46-a2ab-549d9d56c069";
//  public static final String DEFAULT_CONT_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff";
  public static final String DEFAULT_CONT_ID = "b79e573c-d51b-4abc-9916-142c0fae8be3";
>>>>>>> refactored DaosFsClient and its native to make DAOS pool/container/init/finalize common to both FS and Object APIs

  public static DaosFsClient prepareFs(String poolId, String contId) throws Exception {
    DaosFsClient.DaosFsClientBuilder builder = new DaosFsClient.DaosFsClientBuilder();
    builder.poolId(poolId).containerId(contId);
    DaosFsClient client = builder.build();

    try {
      //clear all content
      DaosFile daosFile = client.getFile("/");
      String[] children = daosFile.listChildren();
      for (String child : children) {
        if (child.length() == 0 || ".".equals(child)) {
          continue;
        }
        String path = "/" + child;
        DaosFile childFile = client.getFile(path);
        if (childFile.delete(true)) {
          System.out.println("deleted folder " + path);
        } else {
          System.out.println("failed to delete folder " + path);
        }
        childFile.release();
      }
      daosFile.release();
      return client;
    } catch (Exception e) {
      System.out.println("failed to clear/prepare file system");
      e.printStackTrace();
    }
    return null;
  }

  public static void main(String args[]) throws Exception {
    DaosFsClient client = null;
    try {
      client = prepareFs(DEFAULT_POOL_ID, DEFAULT_CONT_ID);
<<<<<<< HEAD
    } finally {
      client.disconnect();
=======
    }finally {
      client.close();
>>>>>>> refactored DaosFsClient and its native to make DAOS pool/container/init/finalize common to both FS and Object APIs
    }
    if (client != null) {
      System.out.println("quitting");
    }

  }
}

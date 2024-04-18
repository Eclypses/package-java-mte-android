//******************************************************************************
// The MIT License (MIT)
//
// Copyright (c) Eclypses, Inc.
//
// All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//******************************************************************************
package com.eclypses.mte;



import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;



//******************************************************************************
// Class MteSdr
//
// This is the MTE Secure Data Replacement Add-On.
//
// To use, create an object of this type. Next, call initSdr() to initialize.
// Call any of the read*() and write() methods to read and write data and
// strings. Call remove() to remove items. The entire SDR may be removed with
// removeSdr().
//
// The protected methods may be overridden to provide a different backing store
// and timestamp if desired.
//******************************************************************************
public class MteSdr {
  
  //--------------------------------------
  // Exception thrown if MTE errors occur.
  //--------------------------------------
  public class SdrException extends Exception {
    public SdrException(String err) {
      super(err);
    }
    private static final long serialVersionUID = 0;
  }


  
  //----------------------------------------------------------
  // Constructor taking the location for the SDR to use.
  //
  // The default implementation uses the location to specify
  // a directory within the OS' file system.
  // In a derived implementation the location can be anything,
  // e.g. a URL for cloud storage or a table / field name in
  // a database. It may even be ignored if not needed.
  //
  // Default-constructed MKE encoder and decoder are created.
  //----------------------------------------------------------
  public MteSdr(String location) {
    this(new MteMkeEnc(), new MteMkeDec(), location);
  }

  
  //----------------------------------------------------------
  // Constructor taking the MKE encoder/decoder and location
  // for the SDR to use.
  //
  // The default implementation uses the location to specify
  // a directory within the OS' file system.
  // In a derived implementation the location can be anything,
  // e.g. a URL for cloud storage or a table / field name in
  // a database. It may even be ignored if not needed.
  //
  // Note: the MKE encoder/decoder provided to this object
  // cannot be used outside this object as this object will
  // change their states.
  //----------------------------------------------------------
  public MteSdr(MteMkeEnc enc, MteMkeDec dec, String location) {
    // Save the encoder and decoder.
    myEnc = enc;
    myDec = dec;
    
    // Set the callbacks to null to ensure our entropy and
    // nonce will be used and to ensure timestamps are disabled.
    myEnc.setEntropyCallback(null);
    myDec.setEntropyCallback(null);
    myEnc.setNonceCallback(null);
    myDec.setNonceCallback(null);
    myEnc.setTimestampCallback(null);
    myDec.setTimestampCallback(null);
    
    // Save the SDR location.
    mySdrLocation = location;
  }

  
  //-----------------------------------------------------
  // Returns the MKE encoder/decoder in use. These should
  // only be used for information.
  //-----------------------------------------------------
  public MteMkeEnc getEncoder() {
    return myEnc;
  }
  
  
  public MteMkeDec getDecoder() {
    return myDec;
  }

  
  //-------------------------------------------------------
  // Initializes the SDR with the entropy and nonce to use.
  // Throws an exception if the SDR cannot be created.
  //-------------------------------------------------------
  public void initSdr(byte[] entropy, long nonce) throws IOException {
    // Save the entropy and nonce.
    myEntropy = entropy;
    myNonce = nonce;

    // Clear the memory storage.
    memRecords.clear();
    
    // If the SDR location does not exist, create it.
    if (!locationExists(mySdrLocation))
      setupLocation(mySdrLocation);
  }

  
  //--------------------------------------------------
  // Read from storage or memory as data or a string.
  // If the same name exists in memory and on storage,
  // the memory version is read.
  // Throws an exception on I/O error or MTE error.
  //--------------------------------------------------
  public byte[] readData(String key) throws IOException, SdrException {
    MteStatus status;
    MteBase.ArrStatus as;

    // Read the data.
    byte[] encodedAll = memRecords.get(key);
    if (encodedAll == null)
      encodedAll = readRecord(mySdrLocation, key);

    // Extract the timestamp. XOR the nonce into it.
    long nonce = 0;
    for (int i = 0; i < Long.BYTES; ++i)
      nonce += ((long)encodedAll[i] & 0xFF) << (i * 8);
    nonce ^= myNonce;
    
    // Copy the entropy because it will be zeroized.
    // Instantiate with "key" and the SDR entropy and nonce.
    byte[] eCopy = new byte[myEntropy.length];
    System.arraycopy(myEntropy, 0, eCopy, 0, eCopy.length);
    myDec.setEntropy(eCopy);
    myDec.setNonce(nonce);
    status = myDec.instantiate(key);
    if (status != MteStatus.mte_status_success)
      throw new SdrException("Error instantiating decoder (" +
                             MteBase.getStatusName(status) + "): " +
                             MteBase.getStatusDescription(status));

    // Remove the timestamp that is prepended.
    byte[] encoded = new byte[encodedAll.length - Long.BYTES];
    System.arraycopy(encodedAll, Long.BYTES, encoded, 0, encoded.length);

    // Decode the data.
    as = myDec.decode(encoded);
    if (as.status != MteStatus.mte_status_success)
      throw new SdrException("Error decoding data (" +
                             MteBase.getStatusName(as.status) + "): " +
                             MteBase.getStatusDescription(as.status));

    // Return the data.
    return as.arr;
  }
  
  
  public String readString(String key) throws IOException, SdrException {
    // MteBase.getCString is a static protected function;
    // We can access it because we are part of the same package.
    return MteBase.getCString(readData(key));
  }

  
  //----------------------------------------------------------------------------
  // Write the given data or string to storage or memory. If the "key" matches
  // the key of a previously written record, this will overwrite it.
  // If "toMemory" is true, the data or string is saved to memory and not
  // written to permanent storage; there are no restrictions on the contents of
  // the "key" argument.
  // If "toMemory" is false, the data or string is saved to permanent storage in
  // the SDR location set in the constructor; the "key" argument must be a
  // valid name for the given implementation.
  // The overloads that do not take the "toMemory" argument default it to false.
  //
  // Throws an exception on I/O error or MTE error.
  //----------------------------------------------------------------------------
  public void write(String key, byte[] value) throws IOException, SdrException {
    write(key, value, false);
  }
  
  
  public void write(String key,
                    byte[] value,
                    boolean toMemory) throws IOException, SdrException {
    MteStatus status;
    MteBase.ArrStatus as;

    // Get the timestamp. XOR the nonce into it.
    long ts = getTimestamp();
    long nonce = ts ^ myNonce;

    // Copy the entropy because it will be zeroized.
    // Instantiate with "key" and the SDR entropy and nonce.
    byte[] eCopy = new byte[myEntropy.length];
    System.arraycopy(myEntropy, 0, eCopy, 0, eCopy.length);
    myEnc.setEntropy(eCopy);
    myEnc.setNonce(nonce);
    status = myEnc.instantiate(key);
    if (status != MteStatus.mte_status_success)
      throw new SdrException("Error instantiating encoder (" +
                             MteBase.getStatusName(status) + "): " +
                             MteBase.getStatusDescription(status));

    // Encode the data.
    as = myEnc.encode(value);
    if (as.status != MteStatus.mte_status_success)
      throw new SdrException("Error encoding data (" +
                             MteBase.getStatusName(as.status) + "): " +
                             MteBase.getStatusDescription(as.status));

    // Prepend the timestamp to the encoded version.
    byte[] encoded = new byte[as.arr.length + Long.BYTES];
    System.arraycopy(as.arr, 0, encoded, Long.BYTES, as.arr.length);
    for (int i = 0; i < Long.BYTES; ++i)
      encoded[i] = (byte)(ts >> (i * 8));

    if (toMemory) {
      // If saving to memory, add it to the memory map.
      memRecords.put(key, encoded);
    }
    else {
      // Otherwise write it to the SDR.
      writeRecord(mySdrLocation, key, encoded);
    }
  }
  
  
  public void write(String key, String value) throws IOException, SdrException {
    write(key, value.getBytes(StandardCharsets.UTF_8), false);
  }
  
  
  public void write(String key,
                    String value,
                    boolean toMemory) throws IOException, SdrException {
    write(key, value.getBytes(StandardCharsets.UTF_8), toMemory);
  }


  //-----------------------------------------------------------------------
  // Removes an SDR item. If the same name exists in memory and on storage,
  // the memory version is removed.
  //
  // It is not an error to remove an item that does not exist. An exception
  // is thrown if the record exists and cannot be removed.
  //-----------------------------------------------------------------------
  public void remove(String key) throws IOException {
    // Remove from memory if it exists there.
    if (memRecords.containsKey(key))
      memRecords.remove(key);
    else {
      // Remove from the SDR if it exists there.
      removeRecord(mySdrLocation, key);
    }
  }

  
  //-------------------------------------------------------------------
  // Removes the SDR. All memory and storage items are removed.
  // This object is not usable until a new call to initSdr().
  //
  // It is not an error to remove an SDR that does not exist.
  // An exception is thrown if any record in the SDR cannot be removed.
  //-------------------------------------------------------------------
  public void removeSdr() throws IOException {
    // Clear the memory storage.
    memRecords.clear();
    
    // If the SDR directory exists, remove.
    if (locationExists(mySdrLocation)) {
      // Remove each file.
      String[] records = listRecords(mySdrLocation);
      for (String record : records)
        removeRecord(mySdrLocation, record);

      // Remove the SDR directory.
      removeLocation(mySdrLocation);
    }
  }

  
  //--------------------------------------------------------
  // Returns true if the location exists, false if not.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  protected boolean locationExists(String location) {
    File dirFile = new File(location);
    return dirFile.exists();
  }

  
  //--------------------------------------------------------
  // Returns true if the record exists in the location,
  // false if not.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  protected boolean recordExists(String location, String key) {
    File fileFile = new File(location, key);
    return fileFile.exists();
  }

  
  //--------------------------------------------------------
  // Returns a list of records in a location.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  protected String[] listRecords(String location) throws IOException {
    // Get the list of files in the directory.
    File dirFile = new File(location);
    File[] files = dirFile.listFiles();
    if (files == null)
      throw new IOException("Could not list directory: " + location);

    // Get the file basenames.
    String[] records = new String[files.length];
    for (int i = 0; i < files.length; ++i)
      records[i] = files[i].getName();

    // Return the names.
    return records;
  }

  
  //-----------------------------------------------------------
  // Creates a location (directory), including any intermediate
  // directories as necessary.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //-----------------------------------------------------------
  protected void setupLocation(String location) throws IOException {
    File dirFile = new File(location);
    if (!dirFile.mkdirs())
      throw new IOException("Could not create directory: " + location);
  }

  
  //--------------------------------------------------------
  // Reads a record. Returns the record contents.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  protected byte[] readRecord(String location, String key) throws IOException {
    byte[] value;
    File fileFile = new File(location, key);
    try (FileInputStream stream = new FileInputStream(fileFile)) {
      int bytes = (int)fileFile.length();
      value = new byte[bytes];
      if (stream.read(value) != bytes)
        throw new IOException("Error reading: " + fileFile.toString());
    }
    return value;
  }

    
  //--------------------------------------------------------
  // Writes a record.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  protected void writeRecord(String location,
                             String key,
                             byte[] value) throws IOException {
    File fileFile = new File(location, key);
    try (FileOutputStream stream = new FileOutputStream(fileFile)) {
      stream.write(value);
    }
  }

  
  //--------------------------------------------------------
  // Removes a location.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  protected void removeLocation(String location) throws IOException {
    if (locationExists(location)) {
      File dirFile = new File(location);
      if (!dirFile.delete())
        throw new IOException("Could not remove directory: " +
                              dirFile.toString());
    }
  }

  
  //--------------------------------------------------------
  // Removes a record.
  // Throws an exception on failure.
  //
  // Override this method if you implement your own storage.
  //--------------------------------------------------------
  protected void removeRecord(String location, String key) throws IOException {
    if (recordExists(location, key)) {
      File fileFile = new File(location, key);
      if (!fileFile.delete())
        throw new IOException("Could not remove file: " + fileFile.toString());
    }
  }

  
  //----------------------------------------------------------
  // Returns the timestamp, byte swapped to increase the
  // entropy in the upper bytes.
  //
  // Override this method if you implement your own timestamp.
  //----------------------------------------------------------
  protected long getTimestamp() {
    long ts = System.currentTimeMillis();
    return Long.reverseBytes(ts);
  }

  
  // The encoder and decoder.
  private final MteMkeEnc myEnc;
  private final MteMkeDec myDec;
  private byte[] myEntropy;
  private long myNonce;

  // The SDR path.
  private final String mySdrLocation;

  // Memory files.
  private Map<String, byte[]> memRecords = new HashMap<>();
}

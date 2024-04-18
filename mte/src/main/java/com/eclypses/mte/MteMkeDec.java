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
package com.eclypses.mte;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

// Class MteMkeDec
//
// This is the MTE Managed-Key Encryption decoder/decryptor.
//
// To use, create an object of this type, call instantiate(), call decode()
// zero or more times to decode/decrypt each encoded/encrypted data, then
// optionally call uninstantiate() to clear the random state.
//
// Alternatively, the state can be saved any time after instantiate() and
// restored instead of instantiate() to pick up at a known point.
//
// To use as a chunk-based decryptor, call startDecrypt(), call
// decryptChunk() zero or more times to decrypt each chunk of data, then
// finishDecrypt().
public class MteMkeDec extends MteBase
{
  // Constructor using default options. If the library has buildtime options,
  // they are used; otherwise, the options chosen are defined by the
  // MteBase.ourDefault* constants. The default interop is used.
  //
  // The timestamp window and sequence window are set to 0.
  public MteMkeDec()
  {
    this(0, 0);
  }

  // Constructor using default options. If the library has buildtime options,
  // they are used; otherwise, the options chosen are defined by the
  // MteBase.ourDefault* constants. The default interop is used.
  //
  // The timestamp window and sequence window are required.
  public MteMkeDec(long tWindow, int sWindow)
  {
    this(MteBase.getDefaultDrbg(),
         MteBase.getDefaultTokBytes(),
         MteBase.getDefaultVerifiers(),
         MteBase.getDefaultCipher(),
         MteBase.getDefaultHash(),
         tWindow,
         sWindow);
  }

  // Constructor taking the DRBG, token size in bytes, verifiers algorithm,
  // cipher algorithm, hash algorithm, timestamp window, and sequence window.
  public MteMkeDec(MteDrbgs drbg,
                   int tokBytes,
                   MteVerifiers verifiers,
                   MteCiphers cipher,
                   MteHashes hash,
                   long tWindow,
                   int sWindow)
  {
    // Initialize the base.
    initBase(drbg, tokBytes, verifiers, cipher, hash);

    // Get the decoder/decryptor size.
    int bytes = stateBytes(drbg.getValue(),
                           tokBytes,
                           verifiers.getValue(),
                           cipher.getValue(),
                           hash.getValue());
    if (bytes == 0)
    {
      throw new IllegalArgumentException("MteMkeDec: Invalid options.");
    }

    // Allocate the decoder/decryptor.
    myDecoder = ByteBuffer.allocateDirect(bytes);

    // Initialize the decoder state.
    MteStatus status = MteStatus.valueOf(stateInit(myDecoder,
                                                   drbg.getValue(),
                                                   tokBytes,
                                                   verifiers.getValue(),
                                                   cipher.getValue(),
                                                   hash.getValue(),
                                                   tWindow,
                                                   sWindow));
    if (status != MteStatus.mte_status_success)
    {
      throw new IllegalArgumentException("MteMkeDec: Invalid options.");
    }

    // Allocate the save buffers.
    mySaveBuff = new byte[saveBytes(myDecoder)];
    mySaveBuff64 = ByteBuffer.allocateDirect(saveBytesB64(myDecoder));

    // Allocate the decryptor state.
    myDecryptor = ByteBuffer.allocateDirect(decryptStateBytes(myDecoder));
    myCiphBlockBytes = getCiphersBlockBytes(cipher);
    if (myCiphBlockBytes == 0)
    {
      throw new IllegalArgumentException("MteMkeDec: Invalid options.");
    }
  }

  // Instantiate the decoder/decryptor with the personalization string. The
  // entropy and nonce callbacks will be called to get the rest of the seeding
  // material. Returns the status.
  public MteStatus instantiate(byte[] ps)
  {
    return MteStatus.valueOf(instantiate(myDecoder, ps));
  }
  public MteStatus instantiate(String ps)
  {
    return instantiate(ps.getBytes(StandardCharsets.UTF_8));
  }

  // Returns the reseed counter.
  public long getReseedCounter()
  {
    return reseedCounter(myDecoder);
  }

  // Returns the saved state. The Base64 version returns a Base64-encoded
  // saved state instead. On error, null is returned.
  public byte[] saveState()
  {
    MteStatus status = MteStatus.valueOf(stateSave(myDecoder, mySaveBuff));
    return status == MteStatus.mte_status_success ? mySaveBuff : null;
  }
  public String saveStateB64()
  {
    return stateSaveB64(myDecoder, mySaveBuff64);
  }

  // Restore a saved state, which must be the same length as was returned
  // from the saveState() call. The Base64 version takes a Base64-encoded
  // saved state as produced by saveStateB64(). Returns the status.
  public MteStatus restoreState(byte[] saved)
  {
    return MteStatus.valueOf(stateRestore(myDecoder, saved));
  }
  public MteStatus restoreStateB64(String saved)
  {
    return MteStatus.valueOf(stateRestoreB64(myDecoder, saved));
  }

  // Returns the decode buffer size in bytes given the encoded data, offset
  // to the encoded data, and encoded data length in bytes.
  public int getBuffBytes(int encodedBytes) {
    return buffBytes(myDecoder, encodedBytes);
  }
  public int getBuffBytesB64(int encodedBytes) {
    return buffBytesB64(myDecoder, encodedBytes);
  }

  // Decode/decrypt the given encoded/encrypted version. Returns the decoded/
  // decrypted data and status.
  public ArrStatus decode(byte[] encoded)
  {
    // Get the decode buffer requirement and resize if necessary.
    int buffBytes = buffBytes(myDecoder, encoded.length);
    if (buffBytes > myDecBuff.capacity())
    {
      myDecBuff = ByteBuffer.allocateDirect(buffBytes);
    }
    else if (buffBytes == 0)
    {
      myArrStatus.arr = null;
      myArrStatus.status = MteStatus.mte_status_invalid_input;
      return myArrStatus;
    }

    // Decode.
    myDecOff = 0;
    myDecBytes = 0;
    myArrStatus.status = MteStatus.valueOf(decodeB(myDecoder,
                                                   encoded,
                                                   myDecBuff));
    if (statusIsError(myArrStatus.status))
    {
      myArrStatus.arr = null;
      return myArrStatus;
    }

    // Return the decoded part.
    ((Buffer)myDecBuff).position(myDecOff);
    myArrStatus.arr = new byte[myDecBytes];
    myDecBuff.get(myArrStatus.arr);
    ((Buffer)myDecBuff).position(0);
    return myArrStatus;
  }
  public ArrStatus decodeB64(String encoded)
  {
    // Get the decode buffer requirement and resize if necessary.
    int buffBytes = buffBytesB64(myDecoder, encoded.length());
    if (buffBytes > myDecBuff.capacity())
    {
      myDecBuff = ByteBuffer.allocateDirect(buffBytes);
    }

    // Decode.
    myDecOff = 0;
    myDecBytes = 0;
    myArrStatus.status = MteStatus.valueOf(decodeB64B(myDecoder,
                                                      encoded,
                                                      myDecBuff));
    if (statusIsError(myArrStatus.status))
    {
      myArrStatus.arr = null;
      return myArrStatus;
    }

    // Return the decoded part.
    ((Buffer)myDecBuff).position(myDecOff);
    myArrStatus.arr = new byte[myDecBytes];
    myDecBuff.get(myArrStatus.arr);
    ((Buffer)myDecBuff).position(0);
    return myArrStatus;
  }

  // Decode/decrypt the given message to a string. Returns the decoded/decrypted
  // string and status.
  public StrStatus decodeStr(byte[] encoded)
  {
    // Decode.
    ArrStatus as = decode(encoded);
    myStrStatus.status = as.status;
    if (statusIsError(as.status))
    {
      myStrStatus.str = null;
      return myStrStatus;
    }

    // Convert to string.
    myStrStatus.str = getCString(as.arr);
    return myStrStatus;
  }
  public StrStatus decodeStrB64(String encoded)
  {
    // Decode.
    ArrStatus as = decodeB64(encoded);
    myStrStatus.status = as.status;
    if (statusIsError(as.status))
    {
      myStrStatus.str = null;
      return myStrStatus;
    }

    // Convert to string.
    myStrStatus.str = getCString(as.arr);
    return myStrStatus;
  }

  // Decode the given encoded version of the given length at the given offset
  // to the given buffer at the given offset. Returns the offset of the decoded
  // version, length of the decoded version, and status. The decoded buffer
  // must have sufficient length remaining after the offset. Use getBuffBytes()
  // or getBuffBytes64() to determine the buffer requirement for raw or Base64
  // respectively.
  public OffLenStatus decode(byte[] encoded, int encOff, int encBytes,
                             byte[] decoded, int decOff)
  {
    // Decode.
    myDecOff = 0;
    myDecBytes = 0;
    myOffLenStatus.status = MteStatus.valueOf(decodeA(myDecoder,
                                                      encoded, encOff, encBytes,
                                                      decoded, decOff));
    if (statusIsError(myOffLenStatus.status))
    {
      myOffLenStatus.off = 0;
      myOffLenStatus.bytes = 0;
      return myOffLenStatus;
    }

    // Set the decoded offset and length. Return the information.
    myOffLenStatus.off = myDecOff;
    myOffLenStatus.bytes = myDecBytes;
    return myOffLenStatus;
  }
  public OffLenStatus decodeB64(byte[] encoded, int encOff, int encBytes,
                                byte[] decoded, int decOff)
  {
    // Decode.
    myDecOff = 0;
    myDecBytes = 0;
    myOffLenStatus.status =
      MteStatus.valueOf(decodeB64A(myDecoder,
                                   encoded, encOff, encBytes,
                                   decoded, decOff));
    if (statusIsError(myOffLenStatus.status))
    {
      myOffLenStatus.off = 0;
      myOffLenStatus.bytes = 0;
      return myOffLenStatus;
    }

    // Set the decoded offset and length. Return the information.
    myOffLenStatus.off = myDecOff;
    myOffLenStatus.bytes = myDecBytes;
    return myOffLenStatus;
  }

  // Start a chunk-based decryption session. Returns the status.
  public MteStatus startDecrypt()
  {
    return MteStatus.valueOf(decryptStart(myDecoder, myDecryptor));
  }

  // Decrypt a chunk of data in a chunk-based decryption session. Returns the
  // decrypted data. Returns null on error.
  public byte[] decryptChunk(byte[] encrypted)
  {
    // Resize the buffer if necessary.
    int buffBytes = encrypted.length + myCiphBlockBytes;
    if (buffBytes > myDecBuff.capacity())
    {
      myDecBuff = ByteBuffer.allocateDirect(buffBytes);
    }

    // Decrypt the chunk.
    int dBytes = decryptChunkB(myDecoder, myDecryptor, encrypted, myDecBuff);
    if (dBytes < 0)
    {
      return null;
    }

    // Return the decrypted part.
    byte[] decrypted = new byte[dBytes];
    myDecBuff.get(decrypted);
    ((Buffer)myDecBuff).position(0);
    return decrypted;
  }

  // Decrypt a chunk of data at the given offset of the given length in a
  // chunk-based decryption session. Some decrypted data is written to the
  // decrypted buffer starting at decOff. The amount decrypted is returned.
  // Returns -1 on error.
  public int decryptChunk(byte[] encrypted, int encOff, int encBytes,
                          byte[] decrypted, int decOff) {
    // Decrypt the chunk.
    return decryptChunkA(myDecoder, myDecryptor,
                         encrypted, encOff, encBytes,
                         decrypted, decOff);
  }

  // Finish a chunk-based decryption session. Returns the final part of the
  // result and status.
  public ArrStatus finishDecrypt()
  {
    // Finish the decrypt session.
    myDecOff = 0;
    myDecBytes = 0;
    myArrStatus.status = MteStatus.valueOf(decryptFinish(myDecoder,
                                                         myDecryptor));
    if (statusIsError(myArrStatus.status))
    {
      myArrStatus.arr = null;
      return myArrStatus;
    }

    // Return the final decrypted data if there is any.
    if (myDecBytes != 0)
    {
      ((Buffer)myDecryptor).position(myDecOff);
      myArrStatus.arr = new byte[myDecBytes];
      myDecryptor.get(myArrStatus.arr);
      ((Buffer)myDecryptor).position(0);
    }
    else
    {
      myArrStatus.arr = null;
    }
    return myArrStatus;
  }

  // Finish a chunk-based decryption session. Writes the final part of the
  // result to the decrypted buffer starting at off. Sets bytes to the length
  // of the result in bytes. Returns the status. The decrypted buffer must be
  // large enough to hold at least the chosen cipher's block size in the mode
  // of operation.
  public OffLenStatus finishDecrypt(byte[] decrypted, int off)
  {
    // Finish the decrypt session.
    myDecOff = 0;
    myDecBytes = 0;
    myOffLenStatus.status = MteStatus.valueOf(decryptFinish(myDecoder,
                                                            myDecryptor));
    if (statusIsError(myOffLenStatus.status))
    {
      myOffLenStatus.off = 0;
      myOffLenStatus.bytes = 0;
      return myOffLenStatus;
    }

    // Copy the final decrypted data.
    myOffLenStatus.off = off;
    myOffLenStatus.bytes = myDecBytes;
    if (myOffLenStatus.bytes != 0)
    {
      ((Buffer)myDecryptor).position(myDecOff);
      myDecryptor.get(decrypted, off, myOffLenStatus.bytes);
      ((Buffer)myDecryptor).position(0);
    }
    return myOffLenStatus;
  }

  // Returns the timestamp set during encoding or 0 if there is no timestamp.
  public long getEncTs()
  {
    return myEncTs;
  }

  // Returns the timestamp set during decoding or 0 if there is no timestamp.
  public long getDecTs()
  {
    return myDecTs;
  }

  // Returns the number of messages that were skipped to get in sync during the
  // decode or 0 if there is no sequencing.
  public int getMsgSkipped()
  {
    return myMsgSkipped;
  }

  // Uninstantiate the decoder. It is no longer usable after this call.
  // Returns the status.
  public MteStatus uninstantiate()
  {
    return MteStatus.valueOf(uninstantiate(myDecoder));
  }

  // The decoder state.
  private final ByteBuffer myDecoder;

  // Decoder buffer.
  private int myDecOff;
  private int myDecBytes;
  private ByteBuffer myDecBuff = ByteBuffer.allocateDirect(1);

  // State save buffer.
  private final byte[] mySaveBuff;
  private final ByteBuffer mySaveBuff64;

  // Decrypt state.
  private final ByteBuffer myDecryptor;
  private final int myCiphBlockBytes;

  // Return values.
  private final ArrStatus myArrStatus = new ArrStatus();
  private final StrStatus myStrStatus = new StrStatus();
  private final OffLenStatus myOffLenStatus = new OffLenStatus();

  // Decode values.
  private long myEncTs;
  private long myDecTs;
  private int myMsgSkipped;

  // Static initializer.
  static
  {
    // Do one-time init.
    init();
  }

  // Library functions.
  private static native void init();
  private static native int stateBytes(int drbg,
                                       int tokBytes,
                                       int verifiers,
                                       int cipher,
                                       int hash);
  private static native int stateInit(ByteBuffer state,
                                      int drbg,
                                      int tokBytes,
                                      int verifiers,
                                      int cipher,
                                      int hash,
                                      long tWindow,
                                      int sWindow);
  private native int instantiate(ByteBuffer state, byte[] ps);
  private static native long reseedCounter(ByteBuffer state);
  private static native int saveBytes(ByteBuffer state);
  private static native int saveBytesB64(ByteBuffer state);
  private static native int stateSave(ByteBuffer state, byte[] saved);
  private static native String stateSaveB64(ByteBuffer state, ByteBuffer saved);
  private static native int stateRestore(ByteBuffer state, byte[] saved);
  private static native int stateRestoreB64(ByteBuffer state, String saved);
  private static native int buffBytes(ByteBuffer state, int encBytes);
  private static native int buffBytesB64(ByteBuffer state, int encBytes);
  private native int decodeB(ByteBuffer state,
                             byte[] encoded,
                             ByteBuffer decBuff);
  private native int decodeA(ByteBuffer state,
                             byte[] encoded, int encOff, int encBytes,
                             byte[] decoded, int decOff);
  private native int decodeB64B(ByteBuffer state,
                                String encoded,
                                ByteBuffer decBuff);
  private native int decodeB64A(ByteBuffer state,
                                byte[] encoded, int encOff, int encBytes,
                                byte[] decoded, int decOff);
  private static native int decryptStateBytes(ByteBuffer state);
  private static native int decryptStart(ByteBuffer state, ByteBuffer cState);
  private static native int decryptChunkB(ByteBuffer state, ByteBuffer cState,
                                          byte[] encrypted,
                                          ByteBuffer decrypted);
  private static native int decryptChunkA(ByteBuffer state, ByteBuffer cState,
                                          byte[] encrypted,
                                          int encOff, int encBytes,
                                          byte[] decrypted, int decOff);
  private native int decryptFinish(ByteBuffer state, ByteBuffer cState);
  private static native int uninstantiate(ByteBuffer state);
}


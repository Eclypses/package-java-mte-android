<center>
<img src="Eclypses.png" style="width:50%;"/>
</center>

<div align="center" style="font-size:40pt; font-weight:900; font-family:arial; margin-top:50px;" >
The Android Java MTE Library</div>
<br><br><br>

# Introduction 
This AAR library provides the Java language interface code for the Eclypses MTE.

This library contains all of the Java classes which ship with MTE (please refer to the MTE Core Developer Guide for details).

The current version of this library is 4.1.0 (identical to the MTE version being used).
<br><br><br>

# Getting Started
This guide assumes a working knowledge of including an AAR library (either from a local directory on your computer or directly from a git site) in your Android project.
1.	The most simple way to use the library is to list it as a dependency for your app (Module Settings / Dependencies).\
Copy the prebuilt `package-mte-x.x.x-release.aar` file (x.x.x repesenting the version number) from the root directory of this repository to your `./<your_project>/app/libs/` directory. Next, complete steps #2 - #4 in your app's project.
2.	**NOTE - This library requires that the MTE libraries for the platforms to be supported be procured from Eclypses and included either in your app's project or in this package-java-mte-android library.**

3. In order to copy the MTE libraries into your app's project create these directories under `./<your_project>/app/src/main/jniLibs`:
    ```
    /arm64-v8a/ for the ARM64 64-bit platform
    /armeabi-v7a/ for the ARM 32-bit platform
    /x86/ for the Intel x86 32-bit platform
    /x86_64/ for the AMD64 64-bit platform
    ```
4. Copy the MTE libraries (the *.so files) from the MTE Android distribution archives to these directories. For further information about using prebuilt binary libraries please refer to:
https://developer.android.com/ndk/guides/prebuilts
<br><br><br>

# Build Your Own Library With MTE Included
You can build your own package-mte AAR library which includes the MTE libraries you purchased:

Include the MTE libraries into this project in the very same manner you would include them into your app's project as described above in steps #2 to #4. The path to create your directories in would be:

`./<your_library_directory>/mte/src/main/jniLibs`

By combining the MTE libraries with the package-java-mte-android library you will be able to use a single dependency in your app project to include the Java language interface code as well as the MTE libraries. Finally, rebuild the library as a release build and copy the resulting file from\
`./<your_library_directory>/mte/build/outputs/aar/`\
to your project's\
`./<your_project>/app/libs/` directory.
<br><br><br>

<div style="page-break-after: always; break-after: page;"></div>

# Contact Eclypses

<p align="center" style="font-weight: bold; font-size: 20pt;">Email: <a href="mailto:info@eclypses.com">info@eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 20pt;">Web: <a href="https://www.eclypses.com">www.eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 20pt;">Chat with us: <a href="https://developers.eclypses.com/dashboard">Developer Portal</a></p>
<p style="font-size: 8pt; margin-bottom: 0; margin: 100px 24px 30px 24px; " >
<b>All trademarks of Eclypses Inc.</b> may not be used without Eclypses Inc.'s prior written consent. No license for any use thereof has been granted without express written consent. Any unauthorized use thereof may violate copyright laws, trademark laws, privacy and publicity laws and communications regulations and statutes. The names, images and likeness of the Eclypses logo, along with all representations thereof, are valuable intellectual property assets of Eclypses, Inc. Accordingly, no party or parties, without the prior written consent of Eclypses, Inc., (which may be withheld in Eclypses' sole discretion), use or permit the use of any of the Eclypses trademarked names or logos of Eclypses, Inc. for any purpose other than as part of the address for the Premises, or use or permit the use of, for any purpose whatsoever, any image or rendering of, or any design based on, the exterior appearance or profile of the Eclypses trademarks and or logo(s).
</p>

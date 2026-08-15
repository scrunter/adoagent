Option Explicit

Const HelperPath = "C:\Program Files\AdoAgentClusterKey\AdoAgent.ClusterKey.exe"

Dim gConfigId
gConfigId = ""

Function Open()
    On Error Resume Next
    If Resource.PropertyExists("ConfigId") = False Then
        Resource.AddProperty "ConfigId"
        If Err.Number <> 0 Then
            Resource.LogInformation "ADOCK1901 Open: unable to declare ConfigId."
            Err.Clear
            Open = False
            Exit Function
        End If
    End If

    gConfigId = CStr(Resource.ConfigId)
    If Err.Number <> 0 Then
        Resource.LogInformation "ADOCK1901 Open: ConfigId is not configured."
        Err.Clear
        Open = False
        Exit Function
    End If
    On Error GoTo 0

    ' Open is also called while WSFC discovers the script's private-property
    ' schema. An empty value is therefore valid here, but Online still fails
    ' closed because RunHelper requires a canonical GUID.
    If Len(gConfigId) = 0 Then
        Resource.LogInformation "ADOCK1901 Open: ConfigId is not configured."
        Open = True
        Exit Function
    End If

    If Not IsCanonicalGuid(gConfigId) Then
        Resource.LogInformation "ADOCK1902 Open: ConfigId is invalid."
        Open = False
        Exit Function
    End If

    Resource.LogInformation "ADOCK1000 Open: configuration accepted."
    Open = True
End Function

Function Online()
    Online = RunHelper("activate")
End Function

Function LooksAlive()
    LooksAlive = RunHelper("probe --mode quick")
End Function

Function IsAlive()
    IsAlive = RunHelper("probe --mode full")
End Function

Function Offline()
    Resource.LogInformation "ADOCK1400 Offline: active node-protected file retained."
    Offline = True
End Function

Function Close()
    Close = True
End Function

Function Terminate()
    On Error Resume Next
    Resource.LogInformation "ADOCK1500 Terminate: active node-protected file retained."
    On Error GoTo 0
    Terminate = True
End Function

Function RunHelper(arguments)
    Dim shell, commandLine, exitCode, eventCode
    If Not IsCanonicalGuid(gConfigId) Then
        Resource.LogInformation "ADOCK1902 Run: refusing an invalid ConfigId."
        RunHelper = False
        Exit Function
    End If

    Set shell = CreateObject("WScript.Shell")
    commandLine = Chr(34) & HelperPath & Chr(34) & " " & arguments & " --config-id " & gConfigId & " --json"
    exitCode = shell.Run(commandLine, 0, True)
    If Left(arguments, 8) = "activate" Then
        eventCode = "ADOCK1100"
    ElseIf InStr(arguments, "quick") > 0 Then
        eventCode = "ADOCK1200"
    Else
        eventCode = "ADOCK1300"
    End If
    Resource.LogInformation eventCode & " " & Split(arguments, " ")(0) & " exit=" & CStr(exitCode)
    RunHelper = (exitCode = 0)
End Function

Function IsCanonicalGuid(value)
    Dim expression
    Set expression = New RegExp
    expression.Pattern = "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
    expression.Global = False
    IsCanonicalGuid = expression.Test(value)
End Function

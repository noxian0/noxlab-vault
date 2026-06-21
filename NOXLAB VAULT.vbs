Option Explicit

Dim shell, fso, project, scriptPath, pythonPath, command

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

project = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = project & "\src\main.py"
shell.CurrentDirectory = project

If fso.FileExists(project & "\.venv\Scripts\pythonw.exe") Then
    pythonPath = project & "\.venv\Scripts\pythonw.exe"
ElseIf fso.FileExists(project & "\.venv\Scripts\python.exe") Then
    pythonPath = project & "\.venv\Scripts\python.exe"
Else
    MsgBox "NOXLAB VAULT is not set up yet." & vbCrLf & vbCrLf & _
           "Run SETUP.cmd first, then use this shortcut again.", _
           vbExclamation, "NOXLAB VAULT"
    WScript.Quit 1
End If

If Not fso.FileExists(scriptPath) Then
    MsgBox "The app file was not found:" & vbCrLf & scriptPath, _
           vbCritical, "NOXLAB VAULT"
    WScript.Quit 1
End If

command = """" & pythonPath & """ """ & scriptPath & """"
shell.Run command, 1, False

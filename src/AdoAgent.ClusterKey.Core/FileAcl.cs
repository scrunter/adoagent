using System.Security.AccessControl;

namespace AdoAgent.ClusterKey;

public static class FileAcl
{
    private const AccessControlSections PortableSections =
        AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;

    public static string GetSddl(string path)
    {
        FileInfo file = new(path);
        FileSecurity security = file.GetAccessControl(PortableSections);
        return security.GetSecurityDescriptorSddlForm(PortableSections);
    }

    public static void SetSddl(string path, string sddl)
    {
        FileInfo file = new(path);
        FileSecurity security = file.GetAccessControl(PortableSections);
        AccessControlSections sections = 0;
        if (sddl.Contains("O:", StringComparison.OrdinalIgnoreCase))
        {
            sections |= AccessControlSections.Owner;
        }

        if (sddl.Contains("G:", StringComparison.OrdinalIgnoreCase))
        {
            sections |= AccessControlSections.Group;
        }

        if (sddl.Contains("D:", StringComparison.OrdinalIgnoreCase))
        {
            sections |= AccessControlSections.Access;
        }

        if (sections == 0)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The configured file SDDL does not contain owner, group, or DACL information.");
        }

        security.SetSecurityDescriptorSddlForm(sddl, sections);
        file.SetAccessControl(security);
    }

    public static void ValidateSddl(string sddl)
    {
        try
        {
            RawSecurityDescriptor descriptor = new(sddl);
            if (descriptor.DiscretionaryAcl is null)
            {
                throw new ToolException(ExitCode.InvalidConfiguration, "The configured target SDDL must contain a DACL.");
            }
        }
        catch (ArgumentException exception)
        {
            throw new ToolException(ExitCode.InvalidConfiguration, "The configured target file SDDL is invalid.", exception);
        }
    }
}

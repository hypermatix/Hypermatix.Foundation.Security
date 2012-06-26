using System;
using System.Web;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace Hypermatix.Foundation.Security.Windows
{
	/// <summary>
	/// used for connecting to other Logon Providers
	/// </summary>
	public enum LogonProvider
	{
		LOGON32_PROVIDER_DEFAULT		= 0,
		LOGON32_PROVIDER_WINNT40		= 2,
		LOGON32_PROVIDER_WINNT50		= 3
	}

	/// <summary>
	/// Used to change the level of impersonation on remote systems
	/// </summary>
	public enum ImpersonationLevel
	{
		SecurityAnonymous = 0, 
		SecurityIdentification, 
		SecurityImpersonation, 
		SecurityDelegation
	}

	public enum LogonTypes
	{
		//logon types
		LOGON32_LOGON_INTERACTIVE		= 2,
		LOGON32_LOGON_NETWORK			= 3,
		LOGON32_LOGON_BATCH			= 4,

		// Windows2000
		LOGON32_LOGON_NETWORK_CLEARPASSWORD	= 8,
		LOGON32_LOGON_NEW_CREDENTIALS		= 9
	}

	/// <summary>
	/// Impersonate a specific user in the domain.
	/// Note that the user account on the calling process must have 
	/// the SE_TCB_NAME priviledge when running on W2k.
	/// This can be given using Local Policy MMC and adding account to 
	/// "Act as Part of the Operationg System".  
	/// </summary>
	public class ImpersonationHelper
	{
		#region Dll Imports (P/Invoke)
		[DllImport("advapi32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)] 
		public static extern int LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, 
			int dwLogonType, int dwLogonProvider, out IntPtr phToken);

		[DllImport("advapi32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)]
		public extern static int DuplicateToken(IntPtr hToken, int impersonationLevel, ref IntPtr hNewToken);

		[DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)]
		public static extern bool CloseHandle(IntPtr handle);
		#endregion

		#region Private Variables
		private IntPtr token = IntPtr.Zero;
		private IntPtr dupToken = IntPtr.Zero;

		private WindowsImpersonationContext wic = null;
		private LogonProvider _logonProvider;
		private ImpersonationLevel _impersonationLevel;
		private string _originalUser = WindowsIdentity.GetCurrent().Name;
		private LogonTypes _logonType;
		#endregion

		#region Constructors
		public ImpersonationHelper(LogonProvider logonProvider, ImpersonationLevel level, LogonTypes logonType)
		{
			this._logonProvider = logonProvider;
			this._impersonationLevel = level;
			this._logonType = logonType;
		}

		public ImpersonationHelper(LogonProvider logonProvider, ImpersonationLevel level) : this (logonProvider, level, LogonTypes.LOGON32_LOGON_NETWORK) {}

		public ImpersonationHelper(LogonProvider logonProvider) : this (logonProvider, ImpersonationLevel.SecurityImpersonation, LogonTypes.LOGON32_LOGON_NETWORK) {}

		public ImpersonationHelper() : this(LogonProvider.LOGON32_PROVIDER_DEFAULT, ImpersonationLevel.SecurityImpersonation, LogonTypes.LOGON32_LOGON_NETWORK) {}

		#endregion

		#region Public Properties

		public ImpersonationLevel Level
		{
			get { return this._impersonationLevel; }
			set { this._impersonationLevel = value; }
		}

		public LogonTypes LogonType
		{
			get { return this._logonType; }
			set { this._logonType = value; }
		}

		public string CurrentIdentity
		{
			get { return WindowsIdentity.GetCurrent().Name; }
		}

		/// <summary>
		/// Property returns whether or not an impersonation is occurring
		/// </summary>
		public bool Impersonating
		{
			get 
			{
				return (this.CurrentIdentity != this._originalUser);
			}
		}

		#endregion

		#region Public Methods
		/// <summary>
		/// Impersonates a specific user in the domain.  This changes the process
		/// identity to the impersonated user's security context.
		/// </summary>
		public void ImpersonateUser(string username, string domain, string password)
		{
			if (this.Impersonating) 
			{
				throw new System.Security.SecurityException("You are already impersonating " + this.CurrentIdentity);
			}

			int result = LogonUser(username,
				domain,
				password,
				(int)_logonType,
				(int)_logonProvider,
				out token);

			if(result == 0)
			{
				//check the error
				throw new Win32Exception((int)Marshal.GetLastWin32Error());
			}
			else
			{
				if(DuplicateToken(token, (int)this._impersonationLevel, ref dupToken) != 0)
				{
					WindowsIdentity wi = new WindowsIdentity(dupToken);
					wic = wi.Impersonate();
					if(wic == null)
						throw new Exception("Impersonation Failed");
				}
				else
				{
					//check the error
					throw new Win32Exception((int)Marshal.GetLastWin32Error());
				}
			}
		}

		/// <summary>
		/// Reverts back to the original process identity.
		/// </summary>
		public void UndoImpersonation()
		{
			if(this.Impersonating)
			{
				try
				{
					//undo impersonation
					wic.Undo();
				}
				finally
				{
					//release the ref to the pointer		
					CloseHandle(token);
					CloseHandle(dupToken);
				}
			}
		}
		#endregion
	}
}

using System;
using System.Data;
using System.Collections;
using DS = System.DirectoryServices;

namespace Hypermatix.Foundation.Security.Windows
{
    /// <summary>
    /// Helper class for accessing and querying 
    /// ActiveDirectory services over the network
    /// 
    /// Note: to access AD the process calling this class
    /// would tyically need be running as a user with privileges
    /// to connect to the active directory (i.e. a domain user)
    /// If this is called from (for example) an Asp.NET process then
    /// it will be running as the ASPNET (or NETWORK) user. 
    /// Hence the user may have to be prompted for credentials if
    /// called from a Web app. The class functions will temporarily
    /// impersonate from those credentials to permit the function to
    /// complete its task.
    /// </summary>
    public class ActiveDirectoryHelper
    {
        #region Constants
        private const string CLASS_USER = "User";
        private const string PROPERTY_FULLNAME = "Fullname";
        #endregion

        #region Private variables
        private string _user;
        private string _domain;
        private string _password;
        #endregion

        #region Constructors
        public ActiveDirectoryHelper() { }

        public ActiveDirectoryHelper(string user, string domain, string password) : this()
        {
            _user = user;
            _domain = domain;
            _password = password;
        }
        #endregion 

        #region Public methods
        /// <summary>
        ///  Get a list of users from the ADpath (i.e. Class is User and property is Fullname)
        /// </summary>
        public DataSet GetUserList(string ADpath)
        {
            //TODO - extend to allow multiple user properties returned in the dataset (phone, office, etc.)
            return GetList(ADpath, CLASS_USER, PROPERTY_FULLNAME);
        }

        /// <summary>
        ///  Get a list of items of a given class in a given AD path 
        /// </summary>
        public DataSet GetList(string ADpath, string itemClass, string property)
        {
            DS.DirectoryEntry de = null;
            ImpersonationHelper ih = null;

            try
            {
                //To access the AD for browsing, may need to connect as another user than the
                //current running process user. If provider, temporarily impersonate the provided
                //user credentials (with permissions to access ADpath)
                if (_user != null)
                {
                    ih = new ImpersonationHelper(LogonProvider.LOGON32_PROVIDER_WINNT50);
                    ih.ImpersonateUser(_user, _domain, _password);
                    de = new DS.DirectoryEntry(ADpath, _user, _password, DS.AuthenticationTypes.Secure);
                }
                else
                {
                    //Just try using current running process credentials - 
                    //may throw error if user has insufficient network privileges
                    de = new DS.DirectoryEntry(ADpath);
                }

                DS.PropertyCollection props = de.Properties;

                if (de.Name == null)
                {
                    throw new Exception("Failed to connect to Active Directory");
                }
                else
                {
                    //Get the list of "User" type nodes on the returned AD collection
                    DataSet ds = new DataSet();
                    ds.Tables.Add("Items");
                    ds.Tables[0].Columns.Add("Name");
                    foreach (DS.DirectoryEntry de2 in de.Children)
                    {
                        if (de2.Properties["Class"].Value.ToString() == itemClass)
                        {
                            ds.Tables[0].Rows.Add(new object[] { de2.Properties[property] });
                        }
                    }
                    return ds;
                }
            }
            finally
            {
                //Important! Ensure process always reverts back to original running user credentials
                if (ih != null) ih.UndoImpersonation();
            }
        }
        #endregion Instance methods
    }
}

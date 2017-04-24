using System;
using System.Linq;

namespace Miracl
{
    /// <summary>
    /// Detects if we are running inside a unit test.
    /// </summary>
    public static class UnitTestDetector
    {
        static UnitTestDetector()
        {
            string testAssemblyName = "nunit.framework";
            UnitTestDetector.IsInUnitTest = AppDomain.CurrentDomain.GetAssemblies()
                .Any(a => a.FullName.StartsWith(testAssemblyName));
        }

        /// <summary>
        /// Gets a value indicating whether this instance is running in a unit test.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is running in a unit test; otherwise, <c>false</c>.
        /// </value>
        public static bool IsInUnitTest { get; private set; }
    }
}

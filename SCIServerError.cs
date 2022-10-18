using System;

/**
 * A subclass of SCIException that is thrown when the server sends
 * a specific error message that must be displayed to the user.
 */
namespace com.sitemorse.sci
{
    public class SCIServerError : SCIException
    {
        private static long serialVersionUID = -3396387001939624977L;

        public SCIServerError(String message)
            : base(message)
        {

        }
    }
}
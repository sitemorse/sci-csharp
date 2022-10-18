# Sitemorse CMS Integration (SCI) C# Client

## What is Sitemorse INCMS?
Sitemorse **INCMS** allows you to integrate Sitemorse testing with your applications. It was designed to allow a Content Management System (CMS) to utilise the services provided by Sitemorse, but the API can be used in any application where testing of a web page is required.

CMSs usually run behind firewalls within an organisation. This makes it difficult to use an external servicem, such as Sitemorse, to test content within the CMS. The Sitemorse **INCMS** module is designed to run behind the firewall within a CMS or other applciation. It establishes an outbound connection to the Sitemorse servers and handles all requests from Sitemorse for content to test. From a security point of view, a port needs to be open for outbound connection to Sitemorse. This port is, by default, 5372, but it can be set to any other value.

The protocol used to transfer content to Sitemorse for testing is the Sitemorse CMS Integration (SCI) protocol. This handles authentication and communication with Sitemorse servers. The full specification is available on request from sales@Sitemorse.com.

This is a C# implementation of a client for the SCI protocol and makes it much easier for you to perform Sitemorse tests by just calling the client with a licence key and the content to test.

## Licencing
This software is open source but to perform a Sitemorse test requires a valid licence key. A licence key and protocol documentation can be obtained by contacting sales@Sitemorse.com.

In later releases of Sitemorse **INCMS** the ability to pass a user identifier was added as a required value to provide additional services. For backward compatibility with older versions, two styles licence key are used; legacy keys, that do not require a user identifier; and new (the default) keys that will throw an error if no user identifier is provided. If you are unsure which style of key you have, please contact sales@Sitemorse.com.

## Example C# code
To perform a test, the minimum information that is required is the licence key, the URL of content to test, and a user identifier.

The user identifier can be any string. It is used to populate usage reports that allow you to see who is using the service and how often. Typically, when used with a CMS, the CMS user number is passed as the user string. This allows a CMS administrator to work out the real user in the CMS whilst still passing  anonymised information to Sitemorse.

    using com.sitemorse.sci;
    using System.Diagnostics.Contracts;

    class Program
    {
      static void Main(string[] args)
      {
        Console.WriteLine("SCI CSharp Client test harness");
        string testPage = "https://localhost/my-local-page.html";
        string licenceKey = "0123456789ABCDEF";

        SCIClient client = new SCIClient(licenceKey);
        try
        {
          client.User = "id-1234";
          AssessmentResponse response = client.PerformTest(testPage);
          Console.WriteLine(response.Body);
        }
        catch (SCIException e )
        {
          Console.WriteLine( e.Message );
        }
      }
    }

## Nuget
A nuspec is provided should you want to create a nuget package. This is also available as a package in the [Nuget Gallery](https://www.nuget.org/packages/SCIClient/).

## Other versions
Other versions of this client are available in [php](https://github.com/sitemorse/sci-php) and [java](https://github.com/sitemorse/sci-java).
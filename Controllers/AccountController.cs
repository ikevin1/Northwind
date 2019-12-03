using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Owin;
using System.Security.Cryptography;
//using MySql.Data.MySqlClient.Memcached;
using Northwind.Models;
using Microsoft.Rest.Azure.Authentication;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Northwind.Controllers
{
    public class AccountController : Controller
    {
        private UserManager<AppUser> userManager;
        private SignInManager<AppUser> signInManager;
        private IUserValidator<AppUser> userValidator;
        private IPasswordValidator<AppUser> passwordValidator;
        private IPasswordHasher<AppUser> passwordHasher;
        //private UserManager<AppUser> UserTokenProvider;
        //public IUserTokenProvider<AppUser> UserTokenProvider { get; set; }

        public AccountController(UserManager<AppUser> userMgr, SignInManager<AppUser> signInMgr, IUserValidator<AppUser> userValid, IPasswordValidator<AppUser> passValid, IPasswordHasher<AppUser> passwordHash)//, UserManager<AppUser> userTokenProv)
        {
            userManager = userMgr;
            signInManager = signInMgr;
            userValidator = userValid;
            passwordValidator = passValid;
            passwordHasher = passwordHash;
            //UserTokenProvider = userTokenProv;
        }

        //ForAccount Login url
        public IActionResult Login(string returnUrl)
        {
            // return url remembers the user's original request
            ViewBag.returnUrl = returnUrl;
            return View();
        }

        //ForAccount Access Denied url
        public ViewResult AccessDenied() => View();

            //post Account login
        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel details, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                AppUser user = await userManager.FindByEmailAsync(details.Email);
                if (user != null)
                {
                    await signInManager.SignOutAsync();
                    Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.PasswordSignInAsync(user, details.Password, false, false);
                    if (result.Succeeded)
                    {
                        return Redirect(returnUrl ?? "/");
                    }
                }
                ModelState.AddModelError(nameof(LoginModel.Email), "Invalid user or password");
            }
            return View(details);
        }

        public IActionResult ForgotPassword(string returnUrl)
        {
            // return url remembers the user's original request
            ViewBag.returnUrl = returnUrl;
            return View();
        }

        public IActionResult PasswordCode(string returnUrl)
        {
            // return url remembers the user's original request
            ViewBag.returnUrl = returnUrl;
            return View();
        }

        public IActionResult NewPassword(string returnUrl)
        {
            // return url remembers the user's original request
            ViewBag.returnUrl = returnUrl;
            return View();
        }
        public IActionResult Thankyou(string returnUrl)
        {
            // return url remembers the user's original request
            ViewBag.returnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(PassCode details, string returnUrl)
        {
           
            //await userManager.FindByEmailAsync(details.Email);
            //return View("PasswordCode");
            if (ModelState.IsValid)
            {
                AppUser user = await userManager.FindByNameAsync(details.Email);
                if (user == null)
                {
                    ModelState.AddModelError("", "The user either does not exist or is not confirmed.");
                }
                else
                {
                    SmtpClient SmtpClient = new SmtpClient("smtp.gmail.com");
                    SmtpClient.UseDefaultCredentials = false;
                    SmtpClient.Credentials = new NetworkCredential("chocoservices6@gmail.com", "wctcJeff!");
                    SmtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
                    SmtpClient.EnableSsl = true;
                    MailMessage mailMessage = new MailMessage();
                    mailMessage.From = new MailAddress("chocoservices6@gmail.com");
                    mailMessage.To.Add(details.Email);
                    //mailMessage.Body = "jhoiji";
                    var token = await userManager.GeneratePasswordResetTokenAsync(user);
                    mailMessage.Body = "Follow this instruction to have your email/userId reset .\n Click the link to choose a new password with " +
                        "the given token. http://finalnorthwind.azurewebsites.net/Account/NewPassword" + " " + " \n copy and paste the token in the required field \n" + " Token =" + "   " + token; //<a href="NewPassword">New Password</a>
                    mailMessage.Subject = "Requested Reset Password";
                    SmtpClient.Send(mailMessage);
                    //if (user != null)
                    //{
                    //await signInManager.SignOutAsync();B
                    //     string code = await userManager.GeneratePasswordResetTokenAsync(user);
                    //     AppUser callbackUrl = Url.Action("NewPassword", "Account", new { v = user.Id = user.Id, code = code }, protocol: Request.Url.Scheme);
                    //     await userManager.SendEmailAsync(user.Email, "Reset Password",
                    //"Please reset your password by clicking here: <a href=\"" + callbackUrl + "\">NewPassword</a>");
                    //     return View("PasswordCode");
                    return View("PasswordCode");
                }

            }
            return View("ForgotPassword");
        }

        //for the newpasscode
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> NewPassword(NewPassCode details, string returnurl)
        {
            // await userManager.FindByEmailAsync( details.Email);
            if (ModelState.IsValid)
            {
                //return View(details);

                AppUser user = await userManager.FindByNameAsync(details.Email);
                if (user == null)
                {
                    ModelState.AddModelError(nameof(NewPassCode.Email), "Ooops!! Cannot reset password with empty or wrong email/userID");
                    //return RedirectToAction("NewPassword", "Account");
                }

                IdentityResult Token = await userManager.ResetPasswordAsync(user, details.Email, details.Token);
                //AppUser Token = await userManager.FindByEmailAsync(details.Token);
                if (details.Token == null)
                {
                    ModelState.AddModelError(nameof(NewPassCode.Token), "Ooops!! Did you enter a wrong token?");
                    //return RedirectToAction("NewPassword", "Account");
                }

                //if (!await UserTokenProvider.ValidateAsync("NewPassCode" , user,details.Token))
                //{
                //    ModelState.AddModelError(nameof(NewPassCode.Token), "Ooops!! Did you enter a wrong token?");
                //}

                IdentityResult validPass = null;
                if (!string.IsNullOrEmpty(details.NewPassword))
                {
                    validPass = await passwordValidator.ValidateAsync(userManager, user, details.NewPassword);
                    if (validPass.Succeeded)
                    {
                        user.PasswordHash = passwordHasher.HashPassword(user, details.NewPassword);
                    }
                    else
                    {
                        ModelState.AddModelError(nameof(NewPassCode.NewPassword), "Ooops!! Did you enter wrong info?");
                    }
                }

                if ((details.Email == null && validPass == null) || (details.Email == null && details.NewPassword != string.Empty && validPass.Succeeded))
                {
                    IdentityResult result = await userManager.UpdateAsync(user);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Thankyou");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Ooops!! Did you enter a wrong detail?"); ;
                    }

                    ////AppUser IsValid = await userManager.UserTokenProvider.ValidateAsync("NewPassword", details.Token, userManager, user);
                    //user.Email = details.Email;
                    //IdentityResult validEmail = await userValidator.ValidateAsync(userManager, user);
                    //if (!validEmail.Succeeded)
                    //{
                    //    AddErrorsFromResult(validEmail);
                    //}

                    //if (!await userManager.UserTokenProvider.ValidateAsync("NewPassCode", details.Token, userManager, user))
                    //{                
                    //    ModelState.AddModelError(nameof(NewPassCode.Email), "Reset password could not be completed with a wrong token");
                    //    return View("NewPassword");
                    //}

                    //Microsoft.AspNetCore.Identity.SignInResult result = await userManager.ResetPasswordAsync(user.Id, details.Email, details.Password);//var result or microsoft.aspnetcore...
                    //if (result.Succeeded)
                    //{
                    //    return RedirectToAction("Thankyou", "Account");
                    //}
                    //AddErrors(result);
                    //return View();

                }
             
                else
                {
                    ModelState.AddModelError("", "User Not Found");
                }
                
            }
            return View("Thankyou");
            // }
            //ModelState.AddModelError("", "Empty or Invalid entrys.");
            // return RedirectToAction("NewPassword");
        }       

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
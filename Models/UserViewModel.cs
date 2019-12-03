using System.ComponentModel.DataAnnotations;

namespace Northwind.Models
{
    public class CustomerWithPassword
    {
        public Customer Customer { get; set; }
        [UIHint("password"), Required]
        public string Password { get; set; }
    }

    public class LoginModel
    {
        [Required, UIHint("email")]
        public string Email { get; set; }

        [Required, UIHint("password")]
        public string Password { get; set; }
    }

    public class PassCode
    {
        [Required, UIHint("email")]
        public string Email { get; set; }

    }

    public class NewPassCode
    {
        [Required]
        [Display(Name = "Token")]
        public string Token { get; set; }

        [Required, UIHint("email")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        //[StringLength(100, ErrorMessage = "The {0} must be at least {6} characters long.", MinimumLength = 6)]
        [Required, UIHint("newpassword"), Display(Name = "New Password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Required, UIHint("password"), Display(Name = "Confirm new Password")]
        [Compare("NewPassword", ErrorMessage ="The new password must match with the confirm password.")]
        public string ConfirmPassword { get; set; }

        //NewPassCode newPassCode = new NewPassCode()
        //{
        //    //Try to find a way to implement the change fr the changed password
        //};
    }
}
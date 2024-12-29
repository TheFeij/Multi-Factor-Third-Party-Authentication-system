package api

import "fmt"

var (
	ErrUsernameAlreadyExists = fmt.Errorf("نام کاربری از قبل وجود دارد")
	ErrEmailAlreadyExists    = fmt.Errorf("ایمیل از قبل وجود دارد")
)

var (
	ErrUsernameTooShort              = fmt.Errorf("نام کاربری باید حداقل ۴ کاراکتر باشد")
	ErrUsernameTooLong               = fmt.Errorf("نام کاربری باید حداکثر ۶۴ کاراکتر باشد")
	ErrUsernameMustStartWithAlphabet = fmt.Errorf("نام کاربری باید با یک حرف شروع شود")
	ErrUsernameInvalidCharacters     = fmt.Errorf("نام کاربری فقط می‌تواند شامل حروف، اعداد و ـ باشد")
)

var (
	ErrPasswordTooShort               = fmt.Errorf("گذرواژه باید حداقل ۸ کاراکتر باشد")
	ErrPasswordTooLong                = fmt.Errorf("گذرواژه باید حداکثر ۶۴ کاراکتر باشد")
	ErrPasswordInvalidCharacters      = fmt.Errorf("گذرواژه فقط می‌تواند شامل حروف، اعداد و کاراکترهای خاص زیر باشد: _!@#$%%&*.^")
	ErrPasswordMustContainLowercase   = fmt.Errorf("گذرواژه باید حداقل یک حرف کوچک داشته باشد")
	ErrPasswordMustContainUppercase   = fmt.Errorf("گذرواژه باید حداقل یک حرف بزرگ داشته باشد")
	ErrPasswordMustContainDigit       = fmt.Errorf("گذرواژه باید حداقل یک عدد داشته باشد")
	ErrPasswordMustContainSpecialChar = fmt.Errorf("گذرواژه باید حداقل یکی از این کاراکترهای خاص را داشته باشد: _!@#$%%&*.^")
)

var (
	ErrInvalidEmailFormat = fmt.Errorf("لطفا ایمیل وارد کنید")
)

var (
	ErrInternalServer        = fmt.Errorf("مشکلی پیش آمده! لطفا پس از چند دقیقه دوباره امتحان کنید")
	ErrUsernameEmailNotFound = fmt.Errorf("نام کاربری / ایمیل یافت نشد")
	ErrInvalidPassword       = fmt.Errorf("گذرواژه صحیح نیست")
)

var (
	ErrInvalidCredentials = fmt.Errorf("اطلاعات وارد شده صحیح نیست")
	ErrExpiredLoginToken  = fmt.Errorf("جلسه منقضی شده، لطفا مجددا از قسمت ورود به حساب شروع کنید")
	ErrExpiredSignupToken = fmt.Errorf("جلسه منقضی شده، لطفا مجددا از قسمت ثبت‌نام شروع کنید")
)

var (
	ErrUsernameOrEmailISRequired = fmt.Errorf("لطفا نام کاربری یا ایمیل را وارد کنید")
	ErrInvalidRequest            = fmt.Errorf("درخواست نامعتبر است")
)

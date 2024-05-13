from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField, EmailField, BooleanField
from wtforms.fields.choices import SelectField, RadioField
from wtforms.validators import DataRequired


class RegisterForm(FlaskForm):
    name = StringField('Имя пользователя', validators=[DataRequired()])
    surname = StringField('Фамилия', validators=[DataRequired()])
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password_again = PasswordField('Пароль ещё раз', validators=[DataRequired()])
    country = SelectField("Страна", choices=[("Россия", "Россия"), ("Украина", "Украина"), ("Беларусь", "Беларусь"),
                                             ("Казахстан", "Казахстан"), ("Грузия", "Грузия"), ("Армения", "Армения"),
                                             ("Азербайджан", "Азербайджан"), ("Узбекистан", "Узбекистан"),
                                             ("Таджикистан", "Таджикистан"), ("Туркменистан", "Туркменистан"),
                                             ("Кыргыстан", "Кыргыстан"), ("Эстония", "Эстония"), ("Латвия", "Латвия"),
                                             ("Литва", "Литва"), ("США", "США"), ("Германия", "Германия"),
                                             ("Турция", "Турция"), ("Тайланд", "Тайланд"), ("Израиль", "Израиль")])
    city = StringField('Город', validators=[DataRequired()])
    sex = RadioField('Пол', choices=[('мужской', 'мужской'), ('женский', 'женский')])
    submit = SubmitField('Зарегистрироваться')


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')
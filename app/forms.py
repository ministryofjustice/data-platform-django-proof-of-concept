from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired


class DataSourceForm(FlaskForm):
    name = StringField("Data Source Name", validators=[DataRequired()])
    description = TextAreaField("Description")  # Not mandatory
    aws_resource_arn = StringField("AWS Resource ARN", validators=[DataRequired()])
    submit = SubmitField("Create")

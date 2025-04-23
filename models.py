from extensions import db
from datetime import datetime
from flask_login import UserMixin

class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    rol = db.Column(db.String(50))  # admin, jefazo, diseñador, etc.
    nombre_completo = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=True)
    activo = db.Column(db.Boolean, default=True)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    tareas_asignadas = db.relationship('Tarea', backref='asignado_a_rel', foreign_keys='Tarea.asignado_a')

class Cliente(db.Model):
    __tablename__ = 'cliente'
    
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    empresa = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    telefono = db.Column(db.String(20))
    industria = db.Column(db.String(50))
    notas = db.Column(db.Text)
    
    # Relación con tareas
    tareas = db.relationship('Tarea', back_populates='cliente')  # Cambiado a back_populates

class ArchivoTarea(db.Model):
    __tablename__ = 'archivo_tarea'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255))
    ruta = db.Column(db.String(255))
    tipo = db.Column(db.String(20))
    fecha_subida = db.Column(db.DateTime, default=datetime.utcnow)
    tarea_id = db.Column(db.Integer, db.ForeignKey('tarea.id'))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    
    # Relaciones CORREGIDAS:
    tarea_rel = db.relationship('Tarea', back_populates='archivos')
    usuario = db.relationship('Usuario')

class Tarea(db.Model):
    __tablename__ = 'tarea'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    fecha_limite = db.Column(db.Date)
    prioridad = db.Column(db.String(20))
    estado = db.Column(db.String(20), default='pendiente')
    asignado_a = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=True)
    creador_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    
    # Relaciones CORREGIDAS:
    archivos = db.relationship('ArchivoTarea', backref='tarea', cascade='all, delete-orphan')
    asignado = db.relationship('Usuario', back_populates='tareas_asignadas', foreign_keys=[asignado_a])
    cliente = db.relationship('Cliente', back_populates='tareas')
    comentarios = db.relationship('Comentario', backref='tarea_relacionada', cascade='all, delete-orphan')
    creador = db.relationship('Usuario', foreign_keys=[creador_id])

class Comentario(db.Model):
    __tablename__ = 'comentario'
    
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    tarea_id = db.Column(db.Integer, db.ForeignKey('tarea.id'))
    
    # Relaciones CORREGIDAS:
    usuario = db.relationship('Usuario', backref='comentarios_usuario')
    
class Notificacion(db.Model):
    __tablename__ = 'notificacion'
    
    id = db.Column(db.Integer, primary_key=True)
    mensaje = db.Column(db.Text, nullable=False)
    leida = db.Column(db.Boolean, default=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    tipo = db.Column(db.String(50))  # 'asignacion', 'archivo_subido', etc.
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    tarea_id = db.Column(db.Integer, db.ForeignKey('tarea.id'), nullable=False)
    
    # Relaciones
    usuario = db.relationship('Usuario', backref='notificaciones')
    tarea = db.relationship('Tarea')
from datetime import datetime, date
from werkzeug.utils import secure_filename
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from extensions import db
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from weasyprint import HTML
from flask_migrate import Migrate
from functools import wraps
from flask_wtf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from flask import send_from_directory
from flask_login import current_user
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = '1311015'
csrf = CSRFProtect(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from models import Usuario, Cliente, Tarea, ArchivoTarea, Comentario, Notificacion

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])

# Asegúrate que la carpeta exista
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configuración para uploads
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx', 'psd', 'ai'}

app.config['MAX_CONTENT_LENGTH'] = None  # Sin límite
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
                      'png', 'jpg', 'jpeg', 'gif', 'psd', 'ai', 'eps',
                      'mp4', 'mov', 'avi', 'mkv', 'zip', 'rar', 'indd'}

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Archivos permitidos
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def solo_admin_jefazo(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_rol') not in ['admin', 'jefazo']:
            flash('Acceso restringido a administradores', 'danger')
            return redirect(url_for('tareas'))
        return f(*args, **kwargs)
    return decorated_function

# Crear tablas (ejecutar solo una vez)
with app.app_context():
    db.create_all()

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = Usuario.query.get(session['user_id'])
        return {'current_user': user}
    return {'current_user': None}

@app.before_request
def require_login():
    allowed_routes = ['login', 'static']
    if request.endpoint not in allowed_routes and 'user_id' not in session:
        return redirect(url_for('login'))

# Rutas de Autenticación
@app.route('/login', methods=['GET', 'POST'])  # Asegúrate de aceptar ambos métodos
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Usuario y contraseña requeridos', 'error')
            return redirect(url_for('login'))
        
        user = Usuario.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id  # Establece la sesión
            session['user_rol'] = user.rol
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas', 'error')
    
    # Renderiza plantilla para GET
    return render_template('login.html')

@app.before_request
def require_login():
    allowed_routes = ['login', 'static']  # Añade aquí cualquier ruta pública
    if request.endpoint not in allowed_routes and 'user_id' not in session:
        return redirect(url_for('login'))

@app.route('/admin/usuarios', methods=['GET', 'POST'])
def admin_usuarios():
    # Verificar permisos
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = Usuario.query.get(session['user_id'])
    if not user or user.rol != 'admin':
        flash('Acceso restringido a administradores', 'error')
        return redirect(url_for('dashboard'))

    # Lista de roles disponibles
    roles_disponibles = [
        'admin', 
        'jefazo', 
        'Artista 3D', 
        'Artista 2D', 
        'Diseñador Gráfico',
        'Editor',
        'Community Manager'
    ]

    # Procesar formulario de creación
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        rol = request.form.get('rol')
        nombre_completo = request.form.get('nombre_completo')
        email = request.form.get('email')  # Puede ser None

        if not all([username, password, rol, nombre_completo]):
            flash('Complete los campos obligatorios', 'error')
        else:
            try:
                nuevo_usuario = Usuario(
                    username=username,
                    password_hash=generate_password_hash(password),
                    rol=rol,
                    nombre_completo=nombre_completo,
                    email=email if email else None  # Manejo seguro
                )
                db.session.add(nuevo_usuario)
                db.session.commit()
                flash('Usuario creado exitosamente', 'success')
            except IntegrityError:
                db.session.rollback()
                flash('El nombre de usuario ya existe', 'error')

    # Obtener todos los usuarios
    usuarios = Usuario.query.order_by(Usuario.rol, Usuario.nombre_completo).all()
    
    return render_template(
        'admin_usuarios.html',
        usuarios=usuarios,
        roles=roles_disponibles
    )

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

# Rutas de dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    stats = {
        'tareas_pendientes': Tarea.query.filter_by(estado='pendiente').count(),
        'tareas_completadas': Tarea.query.filter_by(estado='completada').count(),
        'total_clientes': Cliente.query.count(),
        'tareas_por_usuario': db.session.query(
            Usuario.nombre_completo,
            db.func.count(Tarea.id)
        ).join(Tarea, Usuario.id == Tarea.asignado_a)
         .group_by(Usuario.nombre_completo)
         .all()
    }
    
    return render_template('dashboard.html', stats=stats)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.context_processor
def inject_common_vars():
    def contar_notificaciones(user_id):
        if not user_id:
            return 0
        return Notificacion.query.filter_by(
            usuario_id=user_id,
            leida=False
        ).count()

    common = {
        'datetime': datetime,
        'now': datetime.now(),
        'contar_notificaciones_no_leidas': contar_notificaciones
    }
    
    return common

# Ruta para gestionar clientes
@app.route('/clientes', methods=['GET', 'POST'])
def clientes():
    # Solo verifica la sesión, no el rol
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # POST solo para admin/jefazo
    if request.method == 'POST':
        if session.get('user_rol') not in ['admin', 'jefazo']:
            flash('Solo administradores pueden agregar clientes', 'error')
            return redirect(url_for('clientes'))
        
        # Creación del cliente (correctamente indentado)
        cliente = Cliente(
            nombre=request.form['nombre'],
            empresa=request.form.get('empresa', ''),  # get() para campos opcionales
            email=request.form['email'],
            telefono=request.form.get('telefono', ''),
            notas=request.form.get('notas', '')
        )
        db.session.add(cliente)
        db.session.commit()
        flash('Cliente añadido', 'success')
        return redirect(url_for('clientes'))  # Redirigir para evitar reenvío del formulario
    
    # Búsqueda (para GET)
    query = request.args.get('q', '')
    if query:
        clientes = Cliente.query.filter(
            (Cliente.nombre.contains(query)) | 
            (Cliente.empresa.contains(query))
        ).all()
    else:
        clientes = Cliente.query.all()
    
    return render_template('clientes.html', clientes=clientes, query=query)

# Ruta para ver detalles de cliente
@app.route('/cliente/<int:id>')
def ver_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    return render_template('detalle_cliente.html', cliente=cliente, tareas=tareas)

# Ruta para crear/ver tareas
@app.route('/tarea/<int:tarea_id>/subir-archivo', methods=['POST'])
def subir_archivo(tarea_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Obtener usuario actual de la sesión
    user_id = session['user_id']
    usuario_actual = Usuario.query.get(user_id)
    
    if not usuario_actual:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('login'))

    if 'archivos[]' not in request.files:
        flash('No se seleccionaron archivos', 'error')
        return redirect(url_for('detalle_tarea', tarea_id=tarea_id))
    
    tarea = Tarea.query.get_or_404(tarea_id)
    
    # Verificar permisos (solo asignado o admin/jefazo puede subir)
    if user_id != tarea.asignado_a and session.get('user_rol') not in ['admin', 'jefazo']:
        flash('No tienes permisos para subir archivos a esta tarea', 'error')
        return redirect(url_for('detalle_tarea', tarea_id=tarea_id))

    # Procesar archivos
    files = request.files.getlist('archivos[]')
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{tarea_id}_{datetime.now().timestamp()}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            nuevo_archivo = ArchivoTarea(
                nombre=file.filename,
                ruta=filename,
                tipo=request.form.get('tipo', 'original'),
                tarea_id=tarea_id,
                usuario_id=user_id
            )
            db.session.add(nuevo_archivo)

    # Determinar a quién notificar
    if user_id == tarea.asignado_a:
        usuario_a_notificar = tarea.creador_id  # Notificar al creador de la tarea
    else:
        usuario_a_notificar = tarea.asignado_a  # Notificar al asignado

    # Crear notificación
    crear_notificacion(
        usuario_id=usuario_a_notificar,
        tarea_id=tarea_id,
        mensaje=f"{usuario_actual.nombre_completo} ha subido archivos en la tarea: {tarea.titulo}",
        tipo='archivo_subido'
    )

    db.session.commit()
    flash('Archivos subidos correctamente', 'success')
    return redirect(url_for('detalle_tarea', tarea_id=tarea_id))

@app.route('/tarea/<int:tarea_id>/completar', methods=['POST'])
@solo_admin_jefazo  # Usa tu decorador de permisos
def completar_tarea(tarea_id):
    tarea = Tarea.query.get_or_404(tarea_id)
    tarea.estado = 'completada'
    db.session.commit()
    flash('Tarea marcada como completada', 'success')
    return redirect(url_for('detalle_tarea', tarea_id=tarea_id))

@app.route('/archivo/<int:archivo_id>/eliminar', methods=['POST'])
def eliminar_archivo(archivo_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    archivo = ArchivoTarea.query.get_or_404(archivo_id)
    
    # Verificar permisos
    if session['user_id'] != archivo.usuario_id and session['user_rol'] not in ['admin', 'jefazo']:
        abort(403)
    
    try:
        # Eliminar archivo físico
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], archivo.ruta))
        # Eliminar registro
        db.session.delete(archivo)
        db.session.commit()
        flash('Archivo eliminado correctamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar: {str(e)}', 'danger')
    
    return redirect(url_for('detalle_tarea', tarea_id=archivo.tarea_id))

@app.route('/tareas')
def tareas():
    page = request.args.get('page', 1, type=int)
    
    # Consulta base con joins
    tareas_query = Tarea.query.options(
        db.joinedload(Tarea.asignado),
        db.joinedload(Tarea.cliente)
    )
    
    # Aplicar filtros si los hay
    if 'estado' in request.args:
        tareas_query = tareas_query.filter_by(estado=request.args['estado'])
    
    # Paginación
    tareas_paginadas = tareas_query.order_by(
        Tarea.fecha_limite.asc()
    ).paginate(page=page, per_page=10)  # 10 items por página
    
    return render_template('tareas.html', 
                         tareas=tareas_paginadas,
                         now=datetime.now().date())

    # Calcular días restantes para cada tarea
    for tarea in tareas_paginadas.items:
        if tarea.fecha_limite:
            tarea.dias_restantes = (tarea.fecha_limite - date.today()).days

    return render_template('tareas.html', tareas=tareas_paginadas)

# Crear tarea
@app.route('/tareas/nueva', methods=['GET', 'POST'])
@solo_admin_jefazo
def crear_tarea():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    usuarios = Usuario.query.filter(Usuario.activo == True).order_by(Usuario.nombre_completo).all()
    clientes = Cliente.query.order_by(Cliente.nombre).all()
    
    if request.method == 'POST':
        try:
            # 1. Crear la tarea
            nueva_tarea = Tarea(
                titulo=request.form['titulo'],
                descripcion=request.form['descripcion'],
                fecha_limite=datetime.strptime(request.form['fecha_limite'], '%Y-%m-%d').date(),
                prioridad=request.form['prioridad'],
                estado='pendiente',
                asignado_a=int(request.form['asignado_a']),
                creador_id=session['user_id'],
                cliente_id=int(request.form['cliente_id']) if request.form['cliente_id'] else None
            )
            db.session.add(nueva_tarea)
            db.session.flush()  # Para obtener el ID
            
            # 2. Procesar archivos adjuntos
            if 'archivos[]' in request.files:
                for file in request.files.getlist('archivos[]'):
                    if file.filename != '':
                        filename = secure_filename(f"ref_{nueva_tarea.id}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        
                        nuevo_archivo = ArchivoTarea(
                            nombre=file.filename,
                            ruta=filename,
                            tipo='referencia',
                            tarea_id=nueva_tarea.id,
                            usuario_id=session['user_id']
                        )
                        db.session.add(nuevo_archivo)
            
            db.session.commit()
            mensaje = f"Te han asignado la tarea: {nueva_tarea.titulo}"
            crear_notificacion(
                usuario_id=nueva_tarea.asignado_a,
                tarea_id=nueva_tarea.id,
                mensaje=mensaje,
                tipo='asignacion'
            )
            flash('Tarea creada con archivos adjuntos', 'success')
            return redirect(url_for('tareas'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
    
    return render_template('crear_tarea.html',
                        usuarios=usuarios,
                        clientes=clientes,
                        now=datetime.now())

# NOTIFICACIONES
def crear_notificacion(usuario_id, tarea_id, mensaje, tipo):
    """Crea una nueva notificación"""
    notificacion = Notificacion(
        usuario_id=usuario_id,
        tarea_id=tarea_id,
        mensaje=mensaje,
        tipo=tipo,
        leida=False
    )
    db.session.add(notificacion)
    db.session.commit()
    return notificacion

# Contar Notificaciones
def contar_notificaciones_no_leidas(usuario_id):
    """Retorna el número de notificaciones no leídas"""
    return Notificacion.query.filter_by(
        usuario_id=usuario_id,
        leida=False
    ).count()

# Ver Notificaiones
@app.route('/notificaciones')
def ver_notificaciones():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Marcar todas como leídas al entrar
    Notificacion.query.filter_by(
        usuario_id=session['user_id'],
        leida=False
    ).update({'leida': True})
    db.session.commit()
    
    notificaciones = Notificacion.query.filter_by(
        usuario_id=session['user_id']
    ).order_by(
        Notificacion.fecha.desc()
    ).all()
    
    return render_template('notificaciones.html', notificaciones=notificaciones)

# Marcar notificaciones como leidas
@app.route('/notificacion/<int:notif_id>/marcar-leida', methods=['POST'])
def marcar_notificacion_leida(notif_id):
    if 'user_id' not in session:
        return jsonify({'error': 'No autorizado'}), 401
    
    notificacion = Notificacion.query.get_or_404(notif_id)
    if notificacion.usuario_id != session['user_id']:
        return jsonify({'error': 'No autorizado'}), 403
    
    notificacion.leida = True
    db.session.commit()
    return jsonify({'success': True})

# Eliminar notificaciones
@app.route('/notificaciones/limpiar', methods=['POST'])
def limpiar_notificaciones():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Marcar todas como leídas
    Notificacion.query.filter_by(usuario_id=session['user_id']).update({'leida': True})
    db.session.commit()
    
    flash('Todas las notificaciones han sido marcadas como leídas', 'success')
    return redirect(url_for('ver_notificaciones'))

# Descargar archivos
@app.route('/descargar/<path:filename>')
def descargar_archivo(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Editar tareas
@app.route('/tarea/editar/<int:tarea_id>', methods=['GET', 'POST'])
def editar_tarea(tarea_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    tarea = Tarea.query.get_or_404(tarea_id)
    
    # Verificar permisos (solo admin/jefazo o el asignado puede editar)
    if session['user_rol'] not in ['admin', 'jefazo'] and session['user_id'] != tarea.asignado_a:
        flash('No tienes permisos para editar esta tarea', 'danger')
        return redirect(url_for('tareas'))

    if request.method == 'POST':
        try:
            tarea.titulo = request.form['titulo']
            tarea.descripcion = request.form['descripcion']
            tarea.fecha_limite = datetime.strptime(request.form['fecha_limite'], '%Y-%m-%d').date()
            tarea.prioridad = request.form['prioridad']
            tarea.estado = request.form['estado']
            tarea.asignado_a = int(request.form['asignado_a'])
            tarea.cliente_id = int(request.form['cliente_id']) if request.form['cliente_id'] else None
            
            db.session.commit()
            flash('Tarea actualizada correctamente ✅', 'success')
            return redirect(url_for('detalle_tarea', tarea_id=tarea.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar: {str(e)} ❌', 'danger')

     # Procesar nuevos archivos
            if 'nuevos_archivos' in request.files:
                for archivo in request.files.getlist('nuevos_archivos'):
                    if archivo.filename != '':
                        filename = f"{tarea.id}_{secure_filename(archivo.filename)}"
                        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        
                        nuevo_archivo = ArchivoTarea(
                            nombre=archivo.filename,
                            ruta=filename,
                            tarea_id=tarea.id,
                            usuario_id=session['user_id']
                        )
                        db.session.add(nuevo_archivo)
            
            db.session.commit()
            flash('Tarea y archivos actualizados ✅', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)} ❌', 'danger')

    # Para GET, mostrar formulario de edición
    usuarios = Usuario.query.all()
    clientes = Cliente.query.all()
    return render_template('editar_tarea.html', 
                         tarea=tarea,
                         usuarios=usuarios,
                         clientes=clientes,
                         now=datetime.now().date())

# Ruta para cambiar estado de tarea
@app.route('/tarea/<int:id>/estado', methods=['POST'])
def cambiar_estado(id):
    tarea = Tarea.query.get_or_404(id)
    tarea.estado = request.form['estado']
    db.session.commit()
    return redirect(url_for('tareas'))

@app.route('/tarea/<int:tarea_id>/comentar', methods=['POST'])
def comentar_tarea(tarea_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    nuevo_comentario = Comentario(
        texto=request.form['texto'],
        usuario_id=session['user_id'],
        tarea_id=tarea_id
    )
    db.session.add(nuevo_comentario)
    db.session.commit()
    return redirect(url_for('detalle_tarea', tarea_id=tarea_id))

@app.route('/tarea/<int:tarea_id>')
def detalle_tarea(tarea_id):
    tarea = Tarea.query.options(
        db.joinedload(Tarea.asignado),
        db.joinedload(Tarea.archivos).joinedload(ArchivoTarea.usuario),
        db.joinedload(Tarea.comentarios).joinedload(Comentario.usuario)
    ).get_or_404(tarea_id)
    return render_template('detalle_tarea.html', tarea=tarea)

# Ruta para editar usuario (añade esto)
@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@solo_admin_jefazo
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            usuario.username = request.form['username']
            usuario.nombre_completo = request.form['nombre_completo']
            usuario.email = request.form.get('email') or None
            usuario.rol = request.form['rol']
            
            if request.form.get('password'):  # Actualizar contraseña solo si se proporciona
                usuario.password_hash = generate_password_hash(request.form['password'])
                
            db.session.commit()
            flash('Usuario actualizado correctamente', 'success')
            return redirect(url_for('admin_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar: {str(e)}', 'danger')
    
    return render_template('editar_usuario.html', 
                        usuario=usuario,
                        roles=['admin', 'jefazo', 'Artista 3D', 'Artista 2D', 'Diseñador Gráfico', 'Editor', 'Community Manager'])

# Ruta para eliminar usuario (añade esto)
@app.route('/admin/usuarios/eliminar/<int:id>', methods=['POST'])
@solo_admin_jefazo
def eliminar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    
    try:
        # Prevenir auto-eliminación
        if usuario.id == session['user_id']:
            flash('No puedes eliminarte a ti mismo', 'danger')
        else:
            db.session.delete(usuario)
            db.session.commit()
            flash('Usuario eliminado correctamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar: {str(e)}', 'danger')
    
    return redirect(url_for('admin_usuarios'))

def generar_reporte():
    if session.get('user_rol') not in ['admin', 'jefazo']:
        return "Acceso denegado", 403
    tareas = Tarea.query.filter_by(estado='completada').all()
    html = render_template('reporte_tareas.html', tareas=tareas)
    return HTML(string=html).write_pdf()

# Crear usuario admin si no existe (solo en desarrollo)
with app.app_context():
    db.create_all()
    
    # Verificar si ya existe un admin
    admin_existente = Usuario.query.filter_by(rol='admin').first()
    if not admin_existente:
        try:
            admin = Usuario(
                username='Fixer',  # Asegúrate de que sea único
                password_hash=generate_password_hash('m.m.1311015@.'),
                rol='admin',
                nombre_completo='Administrador Principal'
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Usuario admin creado: username='admin'")
        except IntegrityError:
            db.session.rollback()
            print("⚠️ El usuario 'admin' ya existe")
        
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

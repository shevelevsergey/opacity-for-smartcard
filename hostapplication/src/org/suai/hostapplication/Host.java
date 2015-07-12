package org.suai.hostapplication;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class Host {

	/* Данный класс отвечает за передачу 
		данных между хост приложением и смарт-картой */
	 
	/* Поля класса */
	private CardTerminal terminal;
	private Card card;
	
	public Host() {
		try {
			TerminalFactory factory = TerminalFactory.getDefault();
			// Получаем список всех доступных считывателей смарт-карт
			List<CardTerminal> terminals = factory.terminals().list();
			// Выбираем первый из списка
			terminal = terminals.get(0);
		} catch (CardException e) {
			e.printStackTrace();
		}
	}
	
	/* Функция для подключения к смарт-карте
	 		Инициализируется поля класса card */
	public void connect() {
		try {
			card = terminal.connect("*");
		} catch (CardException e) {
			e.printStackTrace();
		}
	}
	/* Отключение от смарт-карты */
	public void disconnect() {
		try {
			card.disconnect(false);
		} catch (CardException e) {
			e.printStackTrace();
		}
	}
	
	/* Отправка APDU команды (заголовок + тело)
		Функция возвращает ответ APDU от смарт-карты */
	public byte[] sendCommand(byte[] command) {
		try {
			CardChannel channel = card.getBasicChannel();
			ResponseAPDU respApdu = channel.transmit(new CommandAPDU(command));
			byte[] response = respApdu.getBytes();
			return response;
		} catch (CardException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/* Отправка APDU команды
		Функция возвращает ответ APDU от смарт-карты */
	public byte[] sendCommand(byte[] header, byte[] body) {
		byte[] command = new byte[header.length + body.length];
		System.arraycopy(header, 0, command, 0, header.length);
		System.arraycopy(body, 0, command, header.length, body.length);
		byte[] response = sendCommand(command);
		return response;
	}

	/* Функция возвращает данные из ответа APDU */
	public byte[] getData(byte[] response) {
		byte[] data = new byte[response.length - 2];
		for(int i = 0; i < response.length - 2; i++) {
			data[i] = response[i];
		}
		return data;
	}
	/* Функция возвращает статус выполнения 
					команды APDU смарт-картой */
	public byte[] getStatus(byte[] response) {
		byte[] status = new byte[2];
		status[0] = response[response.length - 2];
		status[1] = response[response.length - 1];
		return status;
	}

}

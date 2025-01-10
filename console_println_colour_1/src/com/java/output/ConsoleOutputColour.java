package com.java.output;

public class ConsoleOutputColour {

	public static void main(String[] args) {
		 // ANSI escape codes for colors
        final String RED = "\u001B[31m";
        final String GREEN = "\u001B[32m";
        final String YELLOW = "\u001B[33m";
        final String BOLD = "\u001B[1m";
        final String ITALIC = "\u001B[3m";
        final String RESET = "\u001B[0m"; // Resets the color

        // Print colored text
        System.out.println(RED + "This text is red!" + RESET);
        System.out.println(GREEN + "This text is green!" + RESET);
        System.out.println(YELLOW + "This text is yellow!" + RESET);
        System.out.println(BOLD + "This text is bold!" + RESET);
        System.out.println(ITALIC + "This text is italic!" + RESET);
        System.out.println(BOLD + ITALIC + "This text is bold and italic!" + RESET);
        System.out.println("This text is default color.");

	}
}
